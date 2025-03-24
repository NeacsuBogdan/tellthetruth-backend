import json
import random

from faker import Faker

fake = Faker()

# Dicționar care mapează categoriile la liste de servicii posibile
category_services = {
    "Restaurant": [
        "Pizza", "Pasta", "Supe", "Grill", "Crispy", "Limonada", "Gin", "Rom", "Whiskey", "Salate"
    ],
    "Pub-uri": [
        "Bere", "Vin", "Cocktailuri", "Snacks", "Muzica live", "Whiskey", "Rom", "Tequila", "Vodka", "Gin"
    ],
    "Cinematografe": [
        "Filme 3D", "Filme 2D", "Popcorn", "Snacks", "Bauturi", "Nachos", "Hot Dogs", "Soda", "Cafea", "Ceai"
    ],
    "Muzee": [
        "Tururi ghidate", "Expozitii temporare", "Magazin de suveniruri", "Cafenea", "Workshops", "Evenimente speciale", "Audio ghiduri", "Expozitii de arta", "Expozitii istorice", "Proiectii de film"
    ],
    "Galerii de artă": [
        "Expozitii permanente", "Expozitii temporare", "Magazin de suveniruri", "Tururi ghidate", "Vernisaje", "Cafenea", "Ateliere de creatie", "Evenimente culturale", "Expoziții de fotografie", "Expoziții de sculptură"
    ],
    "Spa, Sala de sport": [
        "Spa", "Gantere", "Haltere", "Pilates", "Banda de alergat", "Antrenor personal", "Yoga", "Sauna", "Masaj", "Clase de fitness"
    ],
    "Parcuri de distracții": [
        "Roller coaster", "Carusel", "Zona de jocuri", "Restaurante", "Teatru", "Magazin de suveniruri", "Spectacole live", "Casa groazei", "Aqua park", "Zona pentru copii"
    ],
    "Hoteluri": [
        "Cazare", "Restaurant", "Spa", "Piscina", "Room service", "Fitness", "Conferinte", "Bar", "Transfer aeroport", "Servicii de concierge"
    ],
    "Grădini zoologice": [
        "Vizite ghidate", "Cafenea", "Magazin de suveniruri", "Zona de picnic", "Expozitii interactive", "Zonă de joacă", "Spectacole cu animale", "Voluntariat", "Programe educative", "Tururi nocturne"
    ],
    "Cafenele": [
        "Cafea", "Ceai", "Patiserie", "Wi-Fi gratuit", "Muzica live", "Jocuri de societate", "Sandwich-uri", "Smoothies", "Bagels", "Croissante"
    ],
    "Supermarket-uri": [
        "Produse alimentare", "Produse de curatenie", "Cosmetice", "Produse proaspete", "Bauturi", "Produse congelate", "Snacks", "Panificatie", "Produse bio", "Produse lactate"
    ],
    "Teatre": [
        "Spectacole", "Bilete online", "Magazin de suveniruri", "Cafenea", "Meet and greet", "Reprezentatii speciale", "Concerte", "Opera", "Balet", "Workshopuri de teatru"
    ],
    "Piețe": [
        "Produse proaspete", "Artizanat", "Alimente organice", "Flori", "Produse de patiserie", "Fructe și legume", "Produse lactate", "Carne", "Produse apicole", "Ierburi și condimente"
    ],
    "Școli": [
        "Educație", "Bibliotecă", "Activități extracurriculare", "Sport", "Muzică", "Arte", "Programe de voluntariat", "Concursuri școlare", "Excursii educative", "Consiliere școlară"
    ],
    "Universități": [
        "Educație", "Cercetare", "Campus modern", "Bibliotecă", "Laboratoare", "Programe de schimb", "Sporturi universitare", "Cluburi studențești", "Programe de mentorat", "Cursuri online"
    ],
    "Companii aeriene": [
        "Zboruri interne", "Zboruri internationale", "Lounge", "Meniu de bord", "Divertisment în zbor", "Duty free", "Wi-Fi", "Check-in online", "Transfer la aeroport", "Bagaj de cală gratuit"
    ],
    "Companii feroviare": [
        "Trenuri de mare viteza", "Trenuri regionale", "Catering", "Wi-Fi", "Bagaj gratuit", "Reclining seats", "Vagon restaurant", "Divertisment", "Săli de conferințe", "Tururi ghidate"
    ],
    "Clinici": [
        "Consultații", "Analize", "Tratamente", "Farmacie", "Reabilitare", "Fizioterapie", "Radiologie", "Vaccinare", "Laborator", "Telemedicină"
    ],
    "Spitale": [
        "Internare", "Consultații", "Tratamente", "Urgențe", "Chirurgie", "Terapie intensivă", "Radiologie", "Oncologie", "Cardiologie", "Maternitate"
    ]
}

def generate_reviews(num_reviews):
    reviews = []
    for _ in range(num_reviews):
        review = {
            "idU": random.randint(1, 20),
            "scor": random.randint(1, 5),
            "data": fake.date_between(start_date='-1y', end_date='today').strftime('%Y-%m-%d')
        }
        reviews.append(review)
    return reviews

def generate_user_reviews(num_reviews):
    user_reviews = []
    for _ in range(num_reviews):
        user_review = {
            "scor": random.randint(1, 5),
            "data": fake.date_between(start_date='-1y', end_date='today').strftime('%Y-%m-%d')
        }
        user_reviews.append(user_review)
    return user_reviews

def generate_location(id):
    categorie = random.choice(list(category_services.keys()))
    produse_servicii = random.sample(category_services[categorie], k=random.randint(1, 5))
    return {
        "Id": id,
        "Categorie": categorie,
        "Produse/Servicii": ', '.join(produse_servicii),
        "Recenzii": generate_reviews(random.randint(0, 10)),
        "Reviews utilizator": generate_user_reviews(random.randint(0, 5)),
        "Favorite": random.choice(["da", "nu"])
    }

locations = [generate_location(i) for i in range(1, 50)]

with open('data/locations3-1.json', 'w', encoding='utf-8') as f:
    json.dump(locations, f, ensure_ascii=False, indent=4)
