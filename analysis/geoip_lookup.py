import geoip2.database

DB_PATH = "geoip/GeoLite2-City.mmdb"

def lookup_ip(ip: str) -> dict:
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.name,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
            }
    except Exception:
        return {"ip": ip, "country": None, "city": None, "lat": None, "lon": None}