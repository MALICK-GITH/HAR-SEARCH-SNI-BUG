#!/usr/bin/env python3
"""
Database Management for HAR Reader
===================================

PostgreSQL database for storing and retrieving analysis results.

Author: SOLITAIRE HACK
Version: 2.0.0
License: MIT
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor

from env_config import load_local_env


load_local_env()


logger = logging.getLogger(__name__)


class AnalysisDatabase:
    """PostgreSQL database for storing HAR analysis results."""
    
    def __init__(self, db_url: str = None):
        """
        Initialize the database connection and create tables.
        
        Args:
            db_url: PostgreSQL connection URL or None to use environment variable
        """
        if db_url is None:
            db_url = os.getenv('DATABASE_URL')
        
        if not db_url:
            raise ValueError("DATABASE_URL environment variable must be set or db_url must be provided")
        
        self.db_url = db_url
        self._init_db()
    
    def _get_connection(self):
        """Get a database connection."""
        return psycopg2.connect(self.db_url, cursor_factory=RealDictCursor)
    
    def _init_db(self) -> None:
        """Initialize database tables."""
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analyses (
                        id SERIAL PRIMARY KEY,
                        filename TEXT NOT NULL,
                        file_size BIGINT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        total_requests INTEGER,
                        total_domains INTEGER,
                        security_score INTEGER,
                        security_grade TEXT,
                        free_surf_detected BOOLEAN DEFAULT FALSE,
                        free_surf_score INTEGER DEFAULT 0,
                        free_surf_verdict TEXT,
                        host_proxy_tls_score INTEGER DEFAULT 0,
                        host_proxy_tls_verdict TEXT,
                        analysis_data JSONB,
                        metadata JSONB
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_at ON analyses(created_at DESC)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_filename ON analyses(filename)
                """)
                conn.commit()
                logger.info("Database tables initialized successfully")
    
    def save_analysis(
        self,
        filename: str,
        file_size: int,
        analysis_data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Save an analysis result to the database.
        
        Args:
            filename: Name of the HAR file
            file_size: Size of the HAR file in bytes
            analysis_data: Complete analysis results as dictionary
            metadata: Additional metadata (optional)
        
        Returns:
            The ID of the inserted analysis
        """
        try:
            # Extract key metrics from analysis data
            total_requests = analysis_data.get('total_requests', 0)
            total_domains = len(analysis_data.get('domains', {}))
            
            security_data = analysis_data.get('security', {})
            security_score = security_data.get('score', 0)
            security_grade = security_data.get('grade', 'N/A')
            
            free_surf_data = analysis_data.get('free_surf', {})
            free_surf_detected = free_surf_data.get('detected', False)
            free_surf_score = free_surf_data.get('max_score', 0)
            free_surf_verdict = free_surf_data.get('verdict', '')
            
            host_proxy_tls_data = analysis_data.get('host_proxy_tls', {})
            host_proxy_tls_score = host_proxy_tls_data.get('max_score', 0)
            host_proxy_tls_verdict = host_proxy_tls_data.get('verdict', '')
            
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO analyses (
                            filename, file_size, total_requests, total_domains,
                            security_score, security_grade,
                            free_surf_detected, free_surf_score, free_surf_verdict,
                            host_proxy_tls_score, host_proxy_tls_verdict,
                            analysis_data, metadata
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        filename,
                        file_size,
                        total_requests,
                        total_domains,
                        security_score,
                        security_grade,
                        free_surf_detected,
                        free_surf_score,
                        free_surf_verdict,
                        host_proxy_tls_score,
                        host_proxy_tls_verdict,
                        json.dumps(analysis_data),
                        json.dumps(metadata or {})
                    ))
                    result = cursor.fetchone()
                    conn.commit()
                    analysis_id = result['id']
                    logger.info(f"Saved analysis {analysis_id} for file {filename}")
                    return analysis_id
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            raise
    
    def get_all_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve all analyses from the database.
        
        Args:
            limit: Maximum number of analyses to retrieve
        
        Returns:
            List of analysis summaries
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT 
                            id, filename, file_size, created_at,
                            total_requests, total_domains,
                            security_score, security_grade,
                            free_surf_detected, free_surf_score, free_surf_verdict,
                            host_proxy_tls_score, host_proxy_tls_verdict
                        FROM analyses
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (limit,))
                    
                    analyses = []
                    for row in cursor.fetchall():
                        analyses.append({
                            'id': row['id'],
                            'filename': row['filename'],
                            'file_size': row['file_size'],
                            'created_at': row['created_at'],
                            'total_requests': row['total_requests'],
                            'total_domains': row['total_domains'],
                            'security_score': row['security_score'],
                            'security_grade': row['security_grade'],
                            'free_surf_detected': row['free_surf_detected'],
                            'free_surf_score': row['free_surf_score'],
                            'free_surf_verdict': row['free_surf_verdict'],
                            'host_proxy_tls_score': row['host_proxy_tls_score'],
                            'host_proxy_tls_verdict': row['host_proxy_tls_verdict']
                        })
                    
                    return analyses
        except Exception as e:
            logger.error(f"Failed to retrieve analyses: {e}")
            raise
    
    def get_analysis(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific analysis by ID.
        
        Args:
            analysis_id: The ID of the analysis to retrieve
        
        Returns:
            The complete analysis data, or None if not found
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, filename, file_size, created_at, analysis_data, metadata
                        FROM analyses
                        WHERE id = %s
                    """, (analysis_id,))
                    
                    row = cursor.fetchone()
                    if row:
                        return {
                            'id': row['id'],
                            'filename': row['filename'],
                            'file_size': row['file_size'],
                            'created_at': row['created_at'],
                            'analysis_data': row['analysis_data'],
                            'metadata': row['metadata']
                        }
                return None
        except Exception as e:
            logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
            raise
    
    def delete_analysis(self, analysis_id: int) -> bool:
        """
        Delete an analysis from the database.
        
        Args:
            analysis_id: The ID of the analysis to delete
        
        Returns:
            True if deleted, False if not found
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM analyses WHERE id = %s
                    """, (analysis_id,))
                    conn.commit()
                    deleted = cursor.rowcount > 0
                    if deleted:
                        logger.info(f"Deleted analysis {analysis_id}")
                    return deleted
        except Exception as e:
            logger.error(f"Failed to delete analysis {analysis_id}: {e}")
            raise
    
    def search_analyses(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search analyses by filename.
        
        Args:
            query: Search query for filename
            limit: Maximum number of results
        
        Returns:
            List of matching analyses
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT 
                            id, filename, file_size, created_at,
                            total_requests, total_domains,
                            security_score, security_grade,
                            free_surf_detected, free_surf_score, free_surf_verdict,
                            host_proxy_tls_score, host_proxy_tls_verdict
                        FROM analyses
                        WHERE filename LIKE %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (f"%{query}%", limit))
                    
                    analyses = []
                    for row in cursor.fetchall():
                        analyses.append({
                            'id': row['id'],
                            'filename': row['filename'],
                            'file_size': row['file_size'],
                            'created_at': row['created_at'],
                            'total_requests': row['total_requests'],
                            'total_domains': row['total_domains'],
                            'security_score': row['security_score'],
                            'security_grade': row['security_grade'],
                            'free_surf_detected': row['free_surf_detected'],
                            'free_surf_score': row['free_surf_score'],
                            'free_surf_verdict': row['free_surf_verdict'],
                            'host_proxy_tls_score': row['host_proxy_tls_score'],
                            'host_proxy_tls_verdict': row['host_proxy_tls_verdict']
                        })
                    
                    return analyses
        except Exception as e:
            logger.error(f"Failed to search analyses: {e}")
            raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM analyses")
                    total_analyses = cursor.fetchone()['count']
                    
                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE free_surf_detected = TRUE")
                    free_surf_count = cursor.fetchone()['count']
                    
                    cursor.execute("SELECT AVG(security_score) FROM analyses")
                    avg_security_score = cursor.fetchone()['avg'] or 0
                    
                    return {
                        'total_analyses': total_analyses,
                        'free_surf_detected': free_surf_count,
                        'avg_security_score': round(avg_security_score, 2)
                    }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            raise
