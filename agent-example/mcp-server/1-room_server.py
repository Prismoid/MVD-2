import sqlite3
from fastmcp import FastMCP

DB = "room.db"
mcp = FastMCP("Room Server")


def query(sql, args=()):
    with sqlite3.connect(DB) as con:
        return con.execute(sql, args).fetchone()


def room_exists(room: str) -> bool:
    return query("SELECT 1 FROM room_lights WHERE room_id = ?", (room,)) is not None


@mcp.tool
def get_room(room: str) -> dict:
    """Get light status, current temperature, and AC set temperature for a room."""
    row = query(
        """
        SELECT l.is_on, c.current_temperature, c.ac_temperature
        FROM room_lights AS l
        JOIN room_climate AS c ON c.room_id = l.room_id
        WHERE l.room_id = ?
        """,
        (room,),
    )
    if row is None:
        return {"error": f"Unknown room: {room}"}

    is_on, current_temperature, ac_temperature = row
    return {
        "room": room,
        "light": "ON" if is_on else "OFF",
        "current_temperature": current_temperature,
        "ac_temperature": ac_temperature,
    }


@mcp.tool
def get_light(room: str) -> dict:
    """Get the light status of a room (A-1 to A-5)."""
    row = query("SELECT is_on FROM room_lights WHERE room_id = ?", (room,))
    if row is None:
        return {"error": f"Unknown room: {room}"}
    return {"room": room, "light": "ON" if row[0] else "OFF"}


@mcp.tool
def switch_light(room: str, on: bool) -> dict:
    """Switch a room light ON or OFF."""
    if not room_exists(room):
        return {"error": f"Unknown room: {room}"}
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE room_lights SET is_on = ? WHERE room_id = ?", (on, room))
    return {"room": room, "light": "ON" if on else "OFF"}


@mcp.tool
def get_temperature(room: str) -> dict:
    """Get the current measured temperature of a room in degrees Celsius."""
    row = query(
        "SELECT current_temperature FROM room_climate WHERE room_id = ?",
        (room,),
    )
    if row is None:
        return {"error": f"Unknown room: {room}"}
    return {"room": room, "current_temperature": row[0]}


@mcp.tool
def set_room_temperature(room: str, temperature: float) -> dict:
    """Set the current measured room temperature. Intended for simulation/testing."""
    if not room_exists(room):
        return {"error": f"Unknown room: {room}"}
    with sqlite3.connect(DB) as con:
        con.execute(
            "UPDATE room_climate SET current_temperature = ? WHERE room_id = ?",
            (temperature, room),
        )
    return {"room": room, "current_temperature": temperature}


@mcp.tool
def get_ac_temperature(room: str) -> dict:
    """Get the AC set temperature of a room in degrees Celsius."""
    row = query(
        "SELECT ac_temperature FROM room_climate WHERE room_id = ?",
        (room,),
    )
    if row is None:
        return {"error": f"Unknown room: {room}"}
    return {"room": room, "ac_temperature": row[0]}


@mcp.tool
def set_ac_temperature(room: str, temperature: float) -> dict:
    """Set the AC target temperature of a room in degrees Celsius."""
    if not room_exists(room):
        return {"error": f"Unknown room: {room}"}
    with sqlite3.connect(DB) as con:
        con.execute(
            "UPDATE room_climate SET ac_temperature = ? WHERE room_id = ?",
            (temperature, room),
        )
    return {"room": room, "ac_temperature": temperature}


if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=32500)
