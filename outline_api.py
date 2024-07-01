from dataclasses import dataclass
from base64 import b16decode
from typing import Type, Optional, Union
import aiohttp
from aiohttp.client_exceptions import ClientError
from asyncio.exceptions import TimeoutError
from aiohttp.hdrs import METH_GET, METH_POST, METH_DELETE, METH_PUT


@dataclass
class OutlineKey:
    key_id: str
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int
    data_limit: Optional[int]


class OutlineServerError(Exception):
    pass


class Response():
    def __init__(self, status: int, json: Union[dict, None] = None):
        self.status_code = status
        self.json = json


class OutlineServer():
    def __init__(self, api_url: str, cert_sha256: str = None, timeout: float = None):
        self.api_url = api_url
        if cert_sha256:
            self._ssl = aiohttp.Fingerprint(
                b16decode(cert_sha256, casefold=True))
        else:
            self._ssl = None
        self._connector_class: Type[aiohttp.TCPConnector] = aiohttp.TCPConnector
        self._connector_init = dict(ssl=self._ssl)
        if timeout:
            self._timeout = aiohttp.ClientTimeout(timeout)
        else:
            self._timeout = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def get_new_session(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            connector=self._connector_class(**self._connector_init)
        )

    async def get_session(self) -> Optional[aiohttp.ClientSession]:
        if self._session is None or self._session.closed:
            self._session = await self.get_new_session()

        if not self._session._loop.is_running():
            await self._session.close()
            self._session = await self.get_new_session()

        return self._session

    async def make_request(self, method: str, url: str, data: dict = None, timeout: float = None, as_json=False, **kwarg):
        if timeout:
            timeout = aiohttp.ClientTimeout(timeout)
        else:
            timeout = self._timeout
        url = f'{self.api_url}/{url}'
        session = await self.get_session()
        try:
            async with session.request(method, url, data=data, timeout=timeout, **kwarg) as response:
                await response.read()
                if as_json:
                    return Response(response.status, await response.json())
                return Response(response.status)
        except (TimeoutError, ClientError):
            raise OutlineServerError('Server error!')

    async def get_keys(self) -> list[OutlineKey]:
        response = await self.make_request(METH_GET, 'access-keys/', as_json=True)
        if response.status_code == 200 and 'accessKeys' in response.json:
            response_metrics = await self.make_request(METH_GET, 'metrics/transfer', as_json=True)
            if (
                    response_metrics.status_code >= 400
                    or 'bytesTransferredByUserId' not in response_metrics.json
            ):
                raise OutlineServerError('Unable to get metrics')

            response_json = response.json
            result = []
            for key in response_json.get('accessKeys'):
                result.append(
                    OutlineKey(
                        key_id=key.get('id'),
                        name=key.get('name'),
                        password=key.get('password'),
                        port=key.get('port'),
                        method=key.get('method'),
                        access_url=key.get('accessUrl'),
                        data_limit=key.get('dataLimit', {}).get('bytes'),
                        used_bytes=response_metrics.json
                        .get('bytesTransferredByUserId')
                        .get(key.get('id')),
                    )
                )
            return result
        raise OutlineServerError('Unable to retrieve keys')

    async def create_key(self, key_name=None) -> OutlineKey:
        '''Create a new key'''
        response = await self.make_request(METH_POST, 'access-keys/', as_json=True)
        if response.status_code == 201:
            key = response.json
            outline_key = OutlineKey(
                key_id=key.get('id'),
                name=key.get('name'),
                password=key.get('password'),
                port=key.get('port'),
                method=key.get('method'),
                access_url=key.get('accessUrl'),
                used_bytes=0,
                data_limit=None,
            )
            if key_name and await self.rename_key(outline_key.key_id, key_name):
                outline_key.name = key_name
            return outline_key

        raise OutlineServerError('Unable to create key')

    async def delete_key(self, key_id: str) -> bool:
        '''Delete a key'''
        response = await self.make_request(METH_DELETE, f'access-keys/{key_id}')
        return response.status_code == 204

    async def rename_key(self, key_id: str, name: str):
        '''Rename a key'''
        files = {
            'name': name,
        }

        response = await self.make_request(METH_PUT, f'access-keys/{key_id}/name', data=files)
        return response.status_code == 204

    async def add_data_limit(self, key_id: str, limit_bytes: int) -> bool:
        '''Set data limit for a key (in bytes)'''
        data = {'limit': {'bytes': limit_bytes}}

        response = await self.make_request(METH_PUT, f'access-keys/{key_id}/data-limit', json=data)
        return response.status_code == 204

    async def delete_data_limit(self, key_id: str) -> bool:
        '''Removes data limit for a key'''
        response = await self.make_request(METH_DELETE,
                                           f'access-keys/{key_id}/data-limit'
                                           )
        return response.status_code == 204

    async def get_transferred_data(self):
        '''Gets how much data all keys have used
        {
            'bytesTransferredByUserId': {
                '1':1008040941,
                '2':5958113497,
                '3':752221577
            }
        }'''
        response = await self.make_request(METH_GET,  'metrics/transfer', as_json=True)
        if (
                response.status_code >= 400
                or 'bytesTransferredByUserId' not in response.json
        ):
            raise OutlineServerError('Unable to get metrics')
        return response.json

    async def get_server_information(self):
        '''Get information about the server
        {
            'name':'My Server',
            'serverId':'7fda0079-5317-4e5a-bb41-5a431dddae21',
            'metricsEnabled':true,
            'createdTimestampMs':1536613192052,
            'version':'1.0.0',
            'accessKeyDataLimit':{'bytes':8589934592},
            'portForNewAccessKeys':1234,
            'hostnameForAccessKeys':'example.com'
        }
        '''
        response = await self.make_request(METH_GET,  'server', as_json=True)
        if response.status_code != 200:
            raise OutlineServerError(
                'Unable to get information about the server'
            )
        return response.json

    async def set_server_name(self, name: str) -> bool:
        '''Renames the server'''
        data = {'name': name}
        response = await self.make_request(METH_PUT, f'name', json=data)
        return response.status_code == 204

    async def set_hostname(self, hostname: str) -> bool:
        '''Changes the hostname for access keys.
        Must be a valid hostname or IP address.'''
        data = {'hostname': hostname}
        response = await self.make_request(
            METH_PUT, f'server/hostname-for-access-keys', json=data
        )
        return response.status_code == 204

    async def get_metrics_status(self) -> bool:
        '''Returns whether metrics is being shared'''
        response = await self.make_request(METH_GET,  f'metrics/enabled', as_json=True)
        return response.json.get('metricsEnabled')

    async def set_metrics_status(self, status: bool) -> bool:
        '''Enables or disables sharing of metrics'''
        data = {'metricsEnabled': status}
        response = await self.make_request(
            METH_PUT, f'metrics/enabled', json=data
        )
        return response.status_code == 204

    async def set_port_new_for_access_keys(self, port: int) -> bool:
        '''Changes the async def ault port for newly created access keys.
        This can be a port already used for access keys.'''
        data = {'port': port}
        response = await self.make_request(METH_PUT, f'server/port-for-new-access-keys', json=data)
        if response.status_code == 400:
            raise OutlineServerError(
                'The requested port wasnt an integer from 1 through 65535, or the request had no port parameter.'
            )
        elif response.status_code == 409:
            raise OutlineServerError(
                'The requested port was already in use by another service.'
            )
        return response.status_code == 204

    async def set_data_limit_for_all_keys(self, limit_bytes: int) -> bool:
        '''Sets a data transfer limit for all access keys.'''
        data = {'limit': {'bytes': limit_bytes}}
        response = await self.make_request(METH_PUT, f'server/access-key-data-limit', json=data)
        return response.status_code == 204

    async def delete_data_limit_for_all_keys(self) -> bool:
        '''Removes the access key data limit, lifting data transfer restrictions on all access keys.'''
        response = await self.make_request(METH_DELETE, f'server/access-key-data-limit')
        return response.status_code == 204
