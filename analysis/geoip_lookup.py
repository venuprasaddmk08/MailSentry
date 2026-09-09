import geoip2.database

DB_PATH = "geoip/GeoLite2-City.mmdb"
_reader = None

def get_reader():
    global _reader
    if _reader is None:
        _reader = geoip2.database.Reader(DB_PATH)
    return _reader

def lookup_ip(ip: str) -> dict:
    try:
        reader = get_reader()
        response = reader.city(ip)
        city = response.city.name
        country = response.country.name
        lat = response.location.latitude
        lon = response.location.longitude

        if city and country:
            location = f"{city}, {country}"
        elif country:
            location = country
        elif lat is not None and lon is not None:
            location = f"~{lat:.2f}, {lon:.2f}"
        else:
            location = None

        return {
            "ip": ip,
            "country": country,
            "city": city,
            "lat": lat,
            "lon": lon,
            "location": location,
        }
    except Exception:
        return {"ip": ip, "country": None, "city": None, "lat": None, "lon": None, "location": None}