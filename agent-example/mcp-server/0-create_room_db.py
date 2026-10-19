import sqlite3

DB = "room.db"
ROOMS = [
    (f"A-{i}", i % 2 == 1, 24.0 + 0.5 * i, 24.0)
    for i in range(1, 6)
]

with sqlite3.connect(DB) as con:
    con.execute("""
        CREATE TABLE IF NOT EXISTS room_lights (
            room_id TEXT PRIMARY KEY,
            is_on INTEGER NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS room_climate (
            room_id TEXT PRIMARY KEY,
            current_temperature REAL NOT NULL,
            ac_temperature REAL NOT NULL,
            FOREIGN KEY (room_id) REFERENCES room_lights(room_id)
        )
    """)

    con.executemany(
        "INSERT OR REPLACE INTO room_lights (room_id, is_on) VALUES (?, ?)",
        [(room, is_on) for room, is_on, _, _ in ROOMS],
    )
    con.executemany(
        """
        INSERT OR REPLACE INTO room_climate
            (room_id, current_temperature, ac_temperature)
        VALUES (?, ?, ?)
        """,
        [(room, current, ac) for room, _, current, ac in ROOMS],
    )

print("Initialized rooms A-1 to A-5 with light and temperature states")
