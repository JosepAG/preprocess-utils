from pycountry import countries


def country_to_country_code(country: str):
    if country == "Russia":
        country = "Russian Federation"
    return countries.get(name=country).alpha_2
