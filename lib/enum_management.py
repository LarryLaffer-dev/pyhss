# Copyright 2025 volte.io UG (haftungsbeschränkt)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ENUM Management Module for PyHSS

This module provides functionality to manage ENUM (E.164 Number Mapping) entries
in PowerDNS servers. It creates, updates, and deletes NAPTR records according to
RFC 6116 when IMS subscribers are provisioned.

Example ENUM mapping:
  MSISDN: +491721234567
  DNS Name: 7.6.5.4.3.2.1.7.2.9.4.e164.arpa
  NAPTR Record: 10 10 "u" "E2U+sip" "!^.*$!sip:491721234567@ims.mnc001.mcc001.3gppnetwork.org!" .
"""

import requests
from typing import List, Dict, Optional, Tuple, Any


class ENUMManagementError(Exception):
    """Exception raised when ENUM management operations fail."""
    pass


class ENUMClient:
    """
    Client for managing ENUM entries across multiple PowerDNS servers.
    
    Supports multiple PowerDNS API endpoints, each with multiple domains.
    Creates NAPTR records for MSISDNs according to RFC 6116.
    """

    def __init__(self, config: dict, log_tool=None, redis_messaging=None):
        """
        Initialize the ENUM client.
        
        Args:
            config: The PyHSS configuration dictionary containing 'enum' section
            log_tool: Optional LogTool instance for logging
            redis_messaging: Optional RedisMessaging instance for logging
        """
        self.config = config
        self.log_tool = log_tool
        self.redis_messaging = redis_messaging
        
        # ENUM configuration
        self.enum_config = config.get('enum', {})
        self.enabled = self.enum_config.get('enabled', False)
        self.strict_mode = self.enum_config.get('strict_mode', False)
        self.naptr_order = self.enum_config.get('naptr_order', 10)
        self.naptr_preference = self.enum_config.get('naptr_preference', 10)
        self.naptr_ttl = self.enum_config.get('naptr_ttl', 3600)
        self.endpoints = self.enum_config.get('endpoints', [])

    def _log(self, level: str, message: str):
        """Log a message if log_tool is available."""
        if self.log_tool:
            self.log_tool.log(
                service='ENUM',
                level=level,
                message=message,
                redisClient=self.redis_messaging
            )

    @staticmethod
    def msisdn_to_enum_name(msisdn: str, domain: str) -> str:
        """
        Convert an MSISDN to an ENUM DNS name per RFC 6116.
        
        Args:
            msisdn: The MSISDN (e.g., "491721234567" or "+491721234567")
            domain: The ENUM domain (e.g., "e164.arpa")
            
        Returns:
            The ENUM DNS name (e.g., "7.6.5.4.3.2.1.7.2.9.4.e164.arpa")
        """
        # Remove any leading '+' and non-digit characters
        clean_msisdn = ''.join(filter(str.isdigit, msisdn))
        
        # Reverse the digits and join with dots
        reversed_digits = '.'.join(reversed(clean_msisdn))
        
        # Append the domain
        return f"{reversed_digits}.{domain}"

    def generate_naptr_content(self, msisdn: str, sip_domain: str) -> str:
        """
        Generate NAPTR record content for an MSISDN per RFC 6116.
        
        Args:
            msisdn: The MSISDN (digits only, no '+')
            sip_domain: The SIP domain for the URI (e.g., "ims.mnc001.mcc001.3gppnetwork.org")
            
        Returns:
            The NAPTR record content string
        """
        # Clean MSISDN (digits only)
        clean_msisdn = ''.join(filter(str.isdigit, msisdn))
        
        # Format: order preference "flags" "service" "regexp" replacement
        # Example: 10 10 "u" "E2U+sip" "!^.*$!sip:491721234567@ims.example.com!" .
        return (
            f'{self.naptr_order} {self.naptr_preference} "u" "E2U+sip" '
            f'"!^.*$!sip:{clean_msisdn}@{sip_domain}!" .'
        )

    def _parse_msisdn_list(self, msisdn: Optional[str], msisdn_list: Optional[str]) -> List[str]:
        """
        Parse primary MSISDN and msisdn_list into a list of all MSISDNs.
        
        Args:
            msisdn: Primary MSISDN
            msisdn_list: Comma-separated list of additional MSISDNs
            
        Returns:
            List of all MSISDNs (cleaned, digits only)
        """
        all_msisdns = []
        
        if msisdn:
            clean = ''.join(filter(str.isdigit, msisdn))
            if clean:
                all_msisdns.append(clean)
        
        if msisdn_list:
            for m in msisdn_list.split(','):
                clean = ''.join(filter(str.isdigit, m.strip()))
                if clean and clean not in all_msisdns:
                    all_msisdns.append(clean)
        
        return all_msisdns

    def _make_pdns_request(
        self,
        endpoint: dict,
        zone: str,
        rrsets: List[dict]
    ) -> Tuple[bool, Optional[str]]:
        """
        Make a request to PowerDNS API to update records.
        
        Args:
            endpoint: PowerDNS endpoint configuration
            zone: The DNS zone to update
            rrsets: List of rrset changes
            
        Returns:
            Tuple of (success, error_message)
        """
        url = f"{endpoint['url']}/api/v1/servers/localhost/zones/{zone}"
        headers = {
            'X-API-Key': endpoint['api_key'],
            'Content-Type': 'application/json'
        }
        payload = {'rrsets': rrsets}
        
        try:
            response = requests.patch(url, json=payload, headers=headers, timeout=10)
            if response.status_code in (200, 204):
                return True, None
            else:
                error_msg = f"PowerDNS API error: {response.status_code} - {response.text}"
                return False, error_msg
        except requests.exceptions.RequestException as e:
            return False, f"PowerDNS request failed: {str(e)}"

    def create_enum_entries(
        self,
        msisdn: Optional[str],
        msisdn_list: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create ENUM entries for an IMS subscriber's MSISDNs.
        
        Args:
            msisdn: Primary MSISDN
            msisdn_list: Comma-separated list of additional MSISDNs
            
        Returns:
            Dictionary with results per endpoint
            
        Raises:
            ENUMManagementError: If strict_mode is True and any endpoint fails
        """
        if not self.enabled:
            self._log('debug', "ENUM management is disabled, skipping create")
            return {'status': 'disabled'}
        
        all_msisdns = self._parse_msisdn_list(msisdn, msisdn_list)
        if not all_msisdns:
            self._log('debug', "No MSISDNs provided for ENUM creation")
            return {'status': 'no_msisdns'}
        
        self._log('info', f"Creating ENUM entries for MSISDNs: {all_msisdns}")
        
        results = {'status': 'ok', 'endpoints': {}, 'errors': []}
        
        for endpoint in self.endpoints:
            endpoint_name = endpoint.get('name', endpoint.get('url', 'unknown'))
            sip_domain = endpoint.get('sip_domain', '')
            results['endpoints'][endpoint_name] = {'domains': {}}
            
            for domain in endpoint.get('domains', []):
                rrsets = []
                
                for m in all_msisdns:
                    enum_name = self.msisdn_to_enum_name(m, domain)
                    naptr_content = self.generate_naptr_content(m, sip_domain)
                    
                    rrsets.append({
                        'name': enum_name + '.',  # PowerDNS requires trailing dot
                        'type': 'NAPTR',
                        'ttl': self.naptr_ttl,
                        'changetype': 'REPLACE',
                        'records': [{'content': naptr_content, 'disabled': False}]
                    })
                
                success, error = self._make_pdns_request(endpoint, domain, rrsets)
                results['endpoints'][endpoint_name]['domains'][domain] = {
                    'success': success,
                    'msisdns': all_msisdns
                }
                
                if not success:
                    error_detail = f"{endpoint_name}/{domain}: {error}"
                    results['errors'].append(error_detail)
                    self._log('error', f"ENUM create failed - {error_detail}")
                    
                    if self.strict_mode:
                        results['status'] = 'error'
                        raise ENUMManagementError(f"ENUM creation failed: {error_detail}")
                else:
                    self._log('info', f"ENUM entries created on {endpoint_name}/{domain}")
        
        if results['errors']:
            results['status'] = 'partial'
        
        return results

    def delete_enum_entries(
        self,
        msisdn: Optional[str],
        msisdn_list: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Delete ENUM entries for an IMS subscriber's MSISDNs.
        
        Args:
            msisdn: Primary MSISDN
            msisdn_list: Comma-separated list of additional MSISDNs
            
        Returns:
            Dictionary with results per endpoint
            
        Raises:
            ENUMManagementError: If strict_mode is True and any endpoint fails
        """
        if not self.enabled:
            self._log('debug', "ENUM management is disabled, skipping delete")
            return {'status': 'disabled'}
        
        all_msisdns = self._parse_msisdn_list(msisdn, msisdn_list)
        if not all_msisdns:
            self._log('debug', "No MSISDNs provided for ENUM deletion")
            return {'status': 'no_msisdns'}
        
        self._log('info', f"Deleting ENUM entries for MSISDNs: {all_msisdns}")
        
        results = {'status': 'ok', 'endpoints': {}, 'errors': []}
        
        for endpoint in self.endpoints:
            endpoint_name = endpoint.get('name', endpoint.get('url', 'unknown'))
            results['endpoints'][endpoint_name] = {'domains': {}}
            
            for domain in endpoint.get('domains', []):
                rrsets = []
                
                for m in all_msisdns:
                    enum_name = self.msisdn_to_enum_name(m, domain)
                    
                    rrsets.append({
                        'name': enum_name + '.',  # PowerDNS requires trailing dot
                        'type': 'NAPTR',
                        'changetype': 'DELETE',
                        'records': []
                    })
                
                success, error = self._make_pdns_request(endpoint, domain, rrsets)
                results['endpoints'][endpoint_name]['domains'][domain] = {
                    'success': success,
                    'msisdns': all_msisdns
                }
                
                if not success:
                    error_detail = f"{endpoint_name}/{domain}: {error}"
                    results['errors'].append(error_detail)
                    self._log('error', f"ENUM delete failed - {error_detail}")
                    
                    if self.strict_mode:
                        results['status'] = 'error'
                        raise ENUMManagementError(f"ENUM deletion failed: {error_detail}")
                else:
                    self._log('info', f"ENUM entries deleted on {endpoint_name}/{domain}")
        
        if results['errors']:
            results['status'] = 'partial'
        
        return results

    def update_enum_entries(
        self,
        old_msisdn: Optional[str],
        old_msisdn_list: Optional[str],
        new_msisdn: Optional[str],
        new_msisdn_list: Optional[str]
    ) -> Dict[str, Any]:
        """
        Update ENUM entries when MSISDNs change.
        
        Computes the difference between old and new MSISDNs, deletes removed ones,
        and creates new ones.
        
        Args:
            old_msisdn: Previous primary MSISDN
            old_msisdn_list: Previous comma-separated list of additional MSISDNs
            new_msisdn: New primary MSISDN
            new_msisdn_list: New comma-separated list of additional MSISDNs
            
        Returns:
            Dictionary with results
            
        Raises:
            ENUMManagementError: If strict_mode is True and any operation fails
        """
        if not self.enabled:
            self._log('debug', "ENUM management is disabled, skipping update")
            return {'status': 'disabled'}
        
        old_set = set(self._parse_msisdn_list(old_msisdn, old_msisdn_list))
        new_set = set(self._parse_msisdn_list(new_msisdn, new_msisdn_list))
        
        to_delete = old_set - new_set
        to_create = new_set - old_set
        
        self._log('info', f"ENUM update: delete {to_delete}, create {to_create}")
        
        results = {
            'status': 'ok',
            'deleted': [],
            'created': [],
            'errors': []
        }
        
        # Delete removed MSISDNs
        if to_delete:
            delete_list = ','.join(to_delete)
            try:
                delete_result = self.delete_enum_entries(None, delete_list)
                results['deleted'] = list(to_delete)
                if delete_result.get('errors'):
                    results['errors'].extend(delete_result['errors'])
            except ENUMManagementError as e:
                results['errors'].append(str(e))
                if self.strict_mode:
                    results['status'] = 'error'
                    raise
        
        # Create new MSISDNs
        if to_create:
            create_list = ','.join(to_create)
            try:
                create_result = self.create_enum_entries(None, create_list)
                results['created'] = list(to_create)
                if create_result.get('errors'):
                    results['errors'].extend(create_result['errors'])
            except ENUMManagementError as e:
                results['errors'].append(str(e))
                if self.strict_mode:
                    results['status'] = 'error'
                    raise
        
        if results['errors']:
            results['status'] = 'partial'
        
        return results

    def reconcile_all(self, database_client) -> Dict[str, Any]:
        """
        Reconcile all ENUM entries from the database.
        
        Iterates through all IMS subscribers in the database and ensures
        their ENUM entries exist in all configured PowerDNS servers.
        
        Args:
            database_client: Database client instance to query IMS subscribers
            
        Returns:
            Dictionary with reconciliation results
        """
        if not self.enabled:
            self._log('info', "ENUM management is disabled, skipping reconciliation")
            return {'status': 'disabled'}
        
        self._log('info', "Starting ENUM reconciliation")
        
        results = {
            'status': 'ok',
            'processed': 0,
            'succeeded': 0,
            'failed': 0,
            'errors': [],
            'subscribers': []
        }
        
        try:
            # Import IMS_SUBSCRIBER model from database module
            from database import IMS_SUBSCRIBER
            
            # Get all IMS subscribers with pagination (0-based page index)
            page = 0
            page_size = 100
            
            while True:
                subscribers = database_client.getAllPaginated(
                    IMS_SUBSCRIBER,
                    page,
                    page_size
                )
                
                if not subscribers or len(subscribers) == 0:
                    break
                
                for sub in subscribers:
                    results['processed'] += 1
                    msisdn = sub.get('msisdn')
                    msisdn_list = sub.get('msisdn_list')
                    sub_id = sub.get('ims_subscriber_id')
                    
                    try:
                        # Create/update ENUM entries for this subscriber
                        create_result = self.create_enum_entries(msisdn, msisdn_list)
                        
                        if create_result.get('status') in ('ok', 'disabled', 'no_msisdns'):
                            results['succeeded'] += 1
                            results['subscribers'].append({
                                'ims_subscriber_id': sub_id,
                                'msisdn': msisdn,
                                'status': 'ok'
                            })
                        else:
                            results['failed'] += 1
                            results['subscribers'].append({
                                'ims_subscriber_id': sub_id,
                                'msisdn': msisdn,
                                'status': 'partial',
                                'errors': create_result.get('errors', [])
                            })
                    except ENUMManagementError as e:
                        results['failed'] += 1
                        results['errors'].append(f"Subscriber {sub_id}: {str(e)}")
                        results['subscribers'].append({
                            'ims_subscriber_id': sub_id,
                            'msisdn': msisdn,
                            'status': 'error',
                            'error': str(e)
                        })
                
                page += 1
                
                # Safety check to prevent infinite loops
                if page > 10000:
                    self._log('warning', "Reconciliation stopped at page 10000")
                    break
        
        except Exception as e:
            results['status'] = 'error'
            results['errors'].append(f"Reconciliation failed: {str(e)}")
            self._log('error', f"ENUM reconciliation failed: {str(e)}")
        
        if results['failed'] > 0:
            results['status'] = 'partial'
        
        self._log('info', f"ENUM reconciliation complete: {results['processed']} processed, "
                         f"{results['succeeded']} succeeded, {results['failed']} failed")
        
        return results

