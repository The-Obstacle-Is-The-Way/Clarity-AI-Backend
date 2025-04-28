# -*- coding: utf-8 -*-
"""
Database Models for Novamind Digital Twin Backend.

This module contains the SQLAlchemy models for the database.
"""

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class PatientModel(Base):
    __tablename__ = 'patients'
    
    id = Column(Integer, primary_key=True)
    name = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
