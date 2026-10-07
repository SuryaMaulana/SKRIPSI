import pandas as pd

from src.data.session import session_features

BASE = pd.Timestamp("2020-07-17 00:00:00", tz="UTC")


def frame(seconds, statuses, paths):
    ts = pd.Series([BASE + pd.Timedelta(seconds=s) if s is not None else pd.NaT for s in seconds], dtype="datetime64[ns, UTC]")
    return ts, pd.Series(statuses, dtype="Int64"), pd.Series(paths)


def test_trailing_sixty_second_window():
    ts, status, path = frame([0, 0, 30, 59, 60, 119, 120], [200, 404, 404, 200, 403, 200, 200], ["/a", "/a", "/b", "/c", "/a", "/d", "/d"])
    out = session_features(ts, status, path)
    assert out["sess_req_60s"].tolist() == [2, 2, 3, 4, 3, 2, 2]
    assert out["sess_uniq_paths_60s"].tolist() == [1, 1, 2, 3, 3, 2, 1]
    assert out["sess_4xx_ratio_60s"].round(3).tolist() == [0.5, 0.5, 0.667, 0.5, 0.667, 0.5, 0.0]


def test_input_order_does_not_matter():
    ts, status, path = frame([60, 0, 30], [200, 404, 200], ["/x", "/y", "/x"])
    out = session_features(ts, status, path)
    assert out["sess_req_60s"].tolist() == [2, 1, 2]
    assert out["sess_uniq_paths_60s"].tolist() == [1, 1, 2]


def test_missing_timestamp_gives_missing_features():
    ts, status, path = frame([None, 5], [None, 200], [None, "/a"])
    out = session_features(ts, status, path)
    assert out.iloc[0].isna().all()
    assert out["sess_req_60s"].iat[1] == 1
