"""
Modelos de datos para OSINT Framework CTI
PostgreSQL-optimized con índices y relaciones
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class Category(db.Model):
    """Categorías de herramientas OSINT"""
    __tablename__ = 'categories'
    
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    tools = db.relationship('Tool', backref='category', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tools_count': self.tools.count()
        }


class Tool(db.Model):
    """Herramientas OSINT/CTI"""
    __tablename__ = 'tools'
    
    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500), nullable=False)
    category_id = db.Column(db.String(50), db.ForeignKey('categories.id'))
    tags = db.Column(db.JSON, default=list)
    author = db.Column(db.String(100))
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Estadísticas
    clicks = db.relationship('ToolClick', backref='tool', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'category_id': self.category_id,
            'tags': self.tags or [],
            'author': self.author,
            'verified': self.verified,
            'click_count': self.clicks.count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ToolClick(db.Model):
    """Registro de clicks en herramientas"""
    __tablename__ = 'tool_clicks'
    
    id = db.Column(db.Integer, primary_key=True)
    tool_id = db.Column(db.String(100), db.ForeignKey('tools.id'))
    clicked_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(500))


class ThreatActor(db.Model):
    """Actores de amenazas (ransomware groups, APTs)"""
    __tablename__ = 'threat_actors'
    
    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    aliases = db.Column(db.JSON, default=list)
    country = db.Column(db.String(100))
    target_industries = db.Column(db.JSON, default=list)
    first_seen = db.Column(db.Date)
    last_seen = db.Column(db.Date)
    status = db.Column(db.String(20), default='active')  # active, inactive, disrupted
    threat_level = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Datos técnicos
    ransom_notes = db.Column(db.JSON, default=list)
    yara_rules = db.Column(db.JSON, default=list)
    mitre_techniques = db.Column(db.JSON, default=list)
    iocs = db.Column(db.JSON, default=list)
    reference_links = db.Column(db.JSON, default=list)
    
    # Metadatos
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100))
    
    # Relaciones
    related_hashes = db.relationship('HashAnalysis', secondary='actor_hash_relations', 
                                    backref='threat_actors')
    
    def to_dict(self, include_related=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'aliases': self.aliases or [],
            'country': self.country,
            'target_industries': self.target_industries or [],
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'status': self.status,
            'threat_level': self.threat_level,
            'ransom_notes': self.ransom_notes or [],
            'yara_rules': self.yara_rules or [],
            'mitre_techniques': self.mitre_techniques or [],
            'iocs': self.iocs or [],
            'references': self.reference_links or [],
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_related:
            data['related_hashes'] = [h.to_dict() for h in self.related_hashes]
            
        return data


class HashAnalysis(db.Model):
    """Análisis de hashes de malware"""
    __tablename__ = 'hash_analysis'
    
    hash = db.Column(db.String(128), primary_key=True)
    hash_type = db.Column(db.String(20))  # md5, sha1, sha256, sha512
    verdict = db.Column(db.String(20), default='unknown')  # clean, malicious, suspicious, unknown
    malware_family = db.Column(db.String(200))
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    tags = db.Column(db.JSON, default=list)
    vendors_detected = db.Column(db.JSON, default=dict)
    mitre_techniques = db.Column(db.JSON, default=list)
    related_iocs = db.Column(db.JSON, default=list)
    source_apis = db.Column(db.JSON, default=list)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'hash': self.hash,
            'hash_type': self.hash_type,
            'verdict': self.verdict,
            'malware_family': self.malware_family,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'tags': self.tags or [],
            'vendors_detected': self.vendors_detected or {},
            'mitre_techniques': self.mitre_techniques or [],
            'related_iocs': self.related_iocs or [],
            'source_apis': self.source_apis or [],
            'analysis_date': self.analysis_date.isoformat() if self.analysis_date else None
        }


class ActorHashRelation(db.Model):
    """Relación muchos-a-muchos entre actores y hashes"""
    __tablename__ = 'actor_hash_relations'
    
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.String(100), db.ForeignKey('threat_actors.id'))
    hash = db.Column(db.String(128), db.ForeignKey('hash_analysis.hash'))
    confidence_score = db.Column(db.Float, default=0.0)  # 0.0 - 1.0
    relation_type = db.Column(db.String(50))  # uses, similar, attributed
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    """Usuarios del sistema (para autenticación futura)"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='analyst')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AuditLog(db.Model):
    """Logs de auditoría de consultas"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(50))  # search, view, export, login
    resource_type = db.Column(db.String(50))  # actor, hash, tool
    resource_id = db.Column(db.String(200))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')