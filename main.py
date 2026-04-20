from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import sqlite3
import bcrypt
import jwt
import datetime

from db import get_connection

app = FastAPI()

SECRET_KEY = "supersecretkey"


class FilmResponse(BaseModel):
    ID: int
    Nom: str
    Note: Optional[float] = None
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
    email: str
    pseudo: str
    password: str

class LoginBody(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class PreferenceBody(BaseModel):
    genre_id: int


def create_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")

def get_user_id_from_header(authorization: str) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header Authorization manquant ou mal formé")
    token = authorization.split(" ")[1]
    return decode_token(token)


@app.get("/ping")
def ping():
    return {"message": "pong"}


@app.get("/films", response_model=PaginatedResponse)
def get_films(page: int = 1, per_page: int = 20, genre_id: Optional[int] = None):
    offset = (page - 1) * per_page

    with get_connection() as conn:
        cursor = conn.cursor()

        if genre_id:
            cursor.execute(
                "SELECT COUNT(*) FROM Film WHERE Genre_ID = ?",
                (genre_id,)
            )
            total = cursor.fetchone()[0]

            cursor.execute(
                "SELECT * FROM Film WHERE Genre_ID = ? ORDER BY DateSortie DESC LIMIT ? OFFSET ?",
                (genre_id, per_page, offset)
            )
        else:
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
        cursor.execute("SELECT * FROM Film WHERE ID = ?", (film_id,))
        film = cursor.fetchone()

    if film is None:
        raise HTTPException(status_code=404, detail="Film non trouvé")

    return dict(film)


@app.get("/genres", response_model=list[GenreResponse])
def get_genres():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Genre ORDER BY Type ASC")
        genres = [dict(row) for row in cursor.fetchall()]
    return genres


@app.post("/auth/register", response_model=TokenResponse)
def register(body: RegisterBody):
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()

    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?) RETURNING ID",
                (body.email, body.pseudo, hashed)
            )
            user_id = cursor.fetchone()["ID"]
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Email déjà utilisé")

    return {"access_token": create_token(user_id)}


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM Utilisateur WHERE AdresseMail = ?",
            (body.email,)
        )
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
