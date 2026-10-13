from datetime import datetime

from copilot.normalize import normalize_records, parse_time

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def test_sysmon_process_create_maps_fields():
    record = {
        "Channel": SYSMON, "EventID": 1, "Hostname": "WORKSTATION5",
        "UtcTime": "2020-10-18 23:50:05.910", "User": "WORKSTATION5\\wardog",
        "Image": r"C:\Windows\System32\rundll32.exe", "CommandLine": "rundll32.exe comsvcs.dll MiniDump",
        "ParentImage": r"C:\Windows\System32\cmd.exe", "ParentCommandLine": "cmd.exe",
        "ProcessGuid": "{a}", "ParentProcessGuid": "{b}", "Message": "long duplicate text",
        "IntegrityLevel": "High",
    }
    rows, skipped = normalize_records([record], "demo")
    row = rows[0]
    assert skipped == 0
    assert row["ts"] == datetime(2020, 10, 18, 23, 50, 5, 910000)
    assert row["dataset"] == "demo"
    assert row["username"] == "wardog"
    assert row["image"].endswith("rundll32.exe")
    assert row["parent_process_guid"] == "{b}"
    assert '"IntegrityLevel": "High"' in row["extra"]
    assert "Message" not in row["extra"]
    assert "CommandLine" not in row["extra"]


def test_host_channel_and_event_code_are_normalized():
    record = {"Channel": "Security", "EventID": "4688", "Hostname": "WORKSTATION5.theshire.local",
              "@timestamp": "2020-09-21T07:15:27.705Z"}
    row = normalize_records([record], "demo")[0][0]
    assert (row["host"], row["channel"], row["event_code"]) == ("workstation5", "security", 4688)


def test_security_4688_and_sysmon_10_use_their_own_field_names():
    records = [
        {"Channel": "Security", "EventID": 4688, "Hostname": "H", "@timestamp": "2020-09-21T07:15:27.705Z",
         "NewProcessName": r"C:\Windows\System32\schtasks.exe", "SubjectUserName": "pgustavo"},
        {"Channel": SYSMON, "EventID": 10, "Hostname": "H", "UtcTime": "2020-09-21 07:15:28.000",
         "SourceImage": r"C:\Windows\System32\rundll32.exe", "SourceProcessGUID": "{g}",
         "TargetImage": r"C:\windows\system32\lsass.exe"},
    ]
    rows, _ = normalize_records(records, "demo")
    assert rows[0]["image"].endswith("schtasks.exe") and rows[0]["username"] == "pgustavo"
    assert rows[1]["image"].endswith("rundll32.exe") and rows[1]["process_guid"] == "{g}"
    assert rows[1]["target_image"].endswith("lsass.exe")


def test_events_without_utctime_are_shifted_onto_the_sysmon_clock():
    records = [
        {"Channel": SYSMON, "EventID": 1, "Hostname": "H",
         "UtcTime": "2020-10-18 23:50:05.910", "TimeCreated": "2020-10-18 07:50:05.917"},
        {"Channel": "Security", "EventID": 4663, "Hostname": "H", "TimeCreated": "2020-10-18 07:50:06.220"},
    ]
    rows, _ = normalize_records(records, "demo")
    assert rows[1]["ts"] == datetime(2020, 10, 18, 23, 50, 6, 220000)


def test_records_without_a_time_or_event_id_are_skipped():
    records = [
        {"Channel": SYSMON, "EventID": 1, "Hostname": "H"},
        {"Channel": SYSMON, "Hostname": "H", "UtcTime": "2020-10-18 23:50:05.910"},
        {"Channel": SYSMON, "EventID": 1, "Hostname": "H", "UtcTime": "2020-10-18 23:50:05.910"},
    ]
    rows, skipped = normalize_records(records, "demo")
    assert (len(rows), skipped) == (1, 2)


def test_rows_are_sorted_by_time():
    records = [
        {"Channel": SYSMON, "EventID": 1, "Hostname": "H", "UtcTime": "2020-10-18 23:50:07.000"},
        {"Channel": SYSMON, "EventID": 1, "Hostname": "H", "UtcTime": "2020-10-18 23:50:05.000"},
    ]
    rows, _ = normalize_records(records, "demo")
    assert rows[0]["ts"] < rows[1]["ts"]


def test_parse_time_accepts_iso_and_space_formats_and_rejects_junk():
    assert parse_time("2020-10-23T02:36:40.265Z") == datetime(2020, 10, 23, 2, 36, 40, 265000)
    assert parse_time("2020-09-04 03:06:08") == datetime(2020, 9, 4, 3, 6, 8)
    assert parse_time("yesterday") is None
    assert parse_time(None) is None
