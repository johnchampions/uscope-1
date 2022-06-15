from ast import keyword
from http import server
from sqlalchemy import Column, ForeignKey, Integer, String, Float, Boolean, Date, DateTime
from sqlalchemy.orm import declarative_base, relationship
from flask_user import UserMixin
from .db import Base



class ConfigKeys(Base):
    __tablename__ = "configkeys"

    id = Column(Integer, primary_key=True)
    keyname = Column(String)
    keyvalue = Column(String)

    def __init__(self, keyname = None, keyvalue= None):
        self.keyname = keyname
        self.keyvalue = keyvalue

class Place(Base):
    __tablename__ = "place"

    id = Column(Integer, primary_key=True)
    placename = Column(String)
    placegoogleid = Column(Integer, ForeignKey('placegoogle.id', ondelete='CASCADE'))
    vicinity = Column(String)
    street1 = Column(String)
    street2 = Column(String)
    suburb = Column(String)
    postcode = Column(String)
    placestate = Column(String)
    phonenumber = Column(String)
    pluscode = Column(String)
    lastchecked = Column(Date)
    
    

    def __init__(self, placename=None, placegoogleid=None, vicinity=None, street1=None, street2=None, suburb=None, postcode=None,
        placestate=None, phonenumber=None, pluscode=None, lastchecked=None):
        
        self.placename = placename
        self.placegoogleid = placegoogleid
        self.vicinity = vicinity
        self.street1 = street1
        self.street2 = street2
        self.suburb = suburb
        self.postcode = postcode
        self.placestate = placestate
        self.phonenumber = phonenumber
        self.pluscode = pluscode
        self.lastchecked = lastchecked
        

class PlaceGoogle(Base):
    __tablename__ = "placegoogle"

    id = Column(Integer, primary_key=True)
    placeid = Column(Integer, ForeignKey('place.id'))
    business_status = Column(Integer)
    lat = Column(Float)
    lng = Column(Float)
    rating = Column(Float)
    user_ratings_total = Column(Integer)
    google_place_id = Column(String)
    mapurl = Column(String)
    website = Column(String)

    def __init__(self, placeid=None, business_status=None, lat=None, lng=None, rating=None, user_ratings_total=None,
        google_place_id=None, mapurl=None, website=None):

        self.placeid = placeid
        self.business_status = business_status
        self.lat = lat
        self.lng = lng
        self.rating = rating
        self.user_ratings_total = user_ratings_total
        self.google_place_id = google_place_id
        self.mapurl = mapurl
        self.website = website

class KeyWords(Base):
    __tablename__ = "keywords"

    id = Column(Integer, primary_key=True)
    placeid = Column(Integer, ForeignKey('place.id', ondelete='CASCADE'))
    keyword = Column(String)

    def __init__(self, placeid=None, keyword=None):
        self.placeid = placeid
        self.keyword = keyword

class JobList(Base):
    __tablename__ = "joblist"

    id = Column(Integer, primary_key=True)
    pointaddress = Column(String)
    radius = Column(Integer)
    lat = Column(Float)
    lng = Column(Float)
    searchterms = Column(String)
    placecount = Column(Integer)
    complete = Column(Boolean)

    def __init__(self, pointaddress=None, radius=None, lat=None, lng=None, searchterms=None, placecount=None, complete=None):
        self.pointaddress = pointaddress
        self.radius = radius
        self.lat = lat
        self.lng = lng
        self.searchterms = searchterms
        self.placecount = placecount
        self.complete = complete

class JobResults(Base):
    __tablename__ = "jobresults"

    id = Column(Integer, primary_key=True)
    placeid = Column(Integer, ForeignKey('place.id'))
    joblistid = Column(Integer, ForeignKey('joblist.id'))

    def __init__(self, placeid=None, joblistid=None):
        self.placeid = placeid
        self.joblistid = joblistid

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    active = Column('is_active', Boolean, nullable=False, server_default='1')
    email = Column(String(255, collation='NOCASE'), nullable=False, unique=True)
    email_confirmed_at = Column(DateTime())
    password = Column(String(255), nullable=False, server_default='')
    first_name = Column(String(100, collation='NOCASE'), nullable=False, server_default='')
    last_name = Column(String(100, collation='NOCASE'), nullable=False, server_default='')
    roles = relationship('Role', secondary='user_roles')

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer(), primary_key=True)
    name = Column(String(50), unique=True)

class UserRoles(Base):
    __tablename__ = 'user_roles'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'))
    





