from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import sqlite3
import bcrypt
import hmac
import hashlib
import base64
import json
import time

from db import get_connection

app = FastAPI()

SECRET_KEY = "supersecretkey"


class FilmResponse(BaseModel):
    ID: int
    Nom: str
    Note: Optional[float] = None   #Optional indique que le champ n'est pas à remplir obligatoirement
    DateSortie: Optional[int] = None
    Image: Optional[str] = None
    Video: Optional[str] = None
    Genre_ID: Optional[int] = None

class GenreResponse(BaseModel):
    ID: int
    Type: str

class PaginatedResponse(BaseModel):
    data: list[FilmResponse]
    page: int
    per_page: int
    total: int

class RegisterBody(BaseModel):
    email: str                 #ici tous les champs sont à remplir obligatoirement
    pseudo: str
    password: str

class LoginBody(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel): 
    """cette classe vérifie que le jeton d'accès est au bon format et définit le format du JSON renvoyé au client"""
    access_token: str
    token_type: str = "bearer"  #type de token par défaut pour Pydantic

class PreferenceBody(BaseModel):
    genre_id: int


def _b64_encode(data: bytes) -> str:
    
    """cette fonction transforme des données binaires en une chaîne de caractères lisible dans une URL."""
    
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode() #Convertit les octets en Base64 puis en str

def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4 
    return base64.urlsafe_b64decode(s + "=" * padding) #la longueur de la chaîne doit être un multiple de 4 donc on ajoute des =

def create_token(user_id: int) -> str:
    
    """carte d'identité numérique de l'utilisateur. 
       Elle est composée de trois parties header, payload et signature. 
       Personne ne peut modifier le token sans que le serveur ne s'en aperçoive."""
    
    header = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64_encode(json.dumps({"user_id": user_id, "exp": int(time.time()) + 86400}).encode())  #l'expiration est fixée 24h après la connexion
    signature = _b64_encode(
        hmac.new(SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()         #on passe les informations dans une fonction de hash
    )
    return f"{header}.{payload}.{signature}"

def decode_token(token: str) -> int:

    """le serveur valide le token envoyé par l'utilisateur"""
    
    try:
        header, payload, signature = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Token invalide")

    expected = _b64_encode(
        hmac.new(SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()  #le code ré effectue le hasahge. Erreur si le résultat est différent.
    )
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Token invalide")

    data = json.loads(_b64_decode(payload))
    if data.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expiré")

    return data["user_id"]

def get_user_id_from_header(authorization: str) -> int:

    """on vérifie que le token est bien valide (en-tête présent, bon format). sinon, une erreur 401 Unauthorized est levée""" 
    
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header Authorization manquant ou mal formé")
    token = authorization.split(" ")[1]
    return decode_token(token)


@app.get("/ping")                #programme test
def ping():
    return {"message": "pong"}


@app.get("/films", response_model=PaginatedResponse)
def get_films(page: int = 1, per_page: int = 20, genre_id: Optional[int] = None):
    offset = (page - 1) * per_page        # permet de sauter les éléments des pages précédentes

    with get_connection() as conn:
        cursor = conn.cursor()

        if genre_id: #le critère de tri est le genre. Parmi les films restants, ils sont classés du plus récent au plus ancien
            
            cursor.execute("SELECT COUNT(*) FROM Film WHERE Genre_ID = ?", (genre_id,)) #requête SQL pour obtenir le nombre total de films. On laisse =? par sécurité, cela empêche d'avoir accès à toute la base de données. 
            total = cursor.fetchone()[0]
            cursor.execute(
                "SELECT * FROM Film WHERE Genre_ID = ? ORDER BY DateSortie DESC LIMIT ? OFFSET ?",
                (genre_id, per_page, offset)
            )
        else: #la base de données n'a pas de critères restrictifs mais les films sont classés du plus récent au plus ancien
            
            cursor.execute("SELECT COUNT(*) FROM Film")
            total = cursor.fetchone()[0]
            cursor.execute(
                "SELECT * FROM Film ORDER BY DateSortie DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            )

        films = [dict(row) for row in cursor.fetchall()]

    return {"data": films, "page": page, "per_page": per_page, "total": total}


@app.get("/films/{film_id}", response_model=FilmResponse)
def get_film(film_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Film WHERE ID = ?", (film_id,)) #c'est à l'utilisateur de remplir le nom du film. La base de données regarde dans la table Film
        film = cursor.fetchone()

    if film is None:
        raise HTTPException(status_code=404, detail="Film non trouvé")

    return dict(film)


@app.get("/genres", response_model=list[GenreResponse])
def get_genres():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Genre ORDER BY Type ASC") #on ordonne par genre croissant (ASC = ascending)
        genres = [dict(row) for row in cursor.fetchall()]
    return genres


@app.post("/auth/register", response_model=TokenResponse)
def register(body: RegisterBody):
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode() #le mdp est hashé par bcrypt + on ajoute une sécurité supplémentaire avec gensalt: 2 utilisateurs avec le même mdp n'auront pas le même hash

    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?) RETURNING ID",
                (body.email, body.pseudo, hashed)
            )
            user_id = cursor.fetchone()["ID"]
            conn.commit()                 #on valide les modifications de la base de données
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Email déjà utilisé") #le mail a un paramètre UNIQUE dans notre base de données

    return {"access_token": create_token(user_id)}


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        user = cursor.fetchone()

    if user is None or not bcrypt.checkpw(body.password.encode(), user["MotDePasse"].encode()):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    return {"access_token": create_token(user["ID"])}


@app.post("/preferences", status_code=201)
def add_preference(body: PreferenceBody, authorization: str = Header(...)):
    user_id = get_user_id_from_header(authorization)

    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Genre_Utilisateur (ID_Genre, ID_User) VALUES (?, ?)",
                (body.genre_id, user_id)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Préférence déjà ajoutée")

    return {"detail": "Préférence ajoutée"}


@app.delete("/preferences/{genre_id}")
def delete_preference(genre_id: int, authorization: str = Header(...)):
    user_id = get_user_id_from_header(authorization)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM Genre_Utilisateur WHERE ID_Genre = ? AND ID_User = ?",
            (genre_id, user_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence non trouvée")

    return {"detail": "Préférence supprimée"}


@app.get("/preferences/recommendations", response_model=list[FilmResponse])
def get_recommendations(authorization: str = Header(...)):
    user_id = get_user_id_from_header(authorization)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT Film.* FROM Film
            JOIN Genre_Utilisateur ON Film.Genre_ID = Genre_Utilisateur.ID_Genre
            WHERE Genre_Utilisateur.ID_User = ?
            ORDER BY Film.DateSortie DESC
            LIMIT 5
        """, (user_id,))
        films = [dict(row) for row in cursor.fetchall()]

    return films


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
