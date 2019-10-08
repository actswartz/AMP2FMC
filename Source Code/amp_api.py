#!/bin/env python

'''
PURPOSE:
THIS SCRIPT IS A LIBRARY HOUSING ALL THE REST API CALLS TO AMP FOR ENDPOINTS.
THIS SCRIPT IS NOT MEANT TO BE EXECUTED BY ITSELF. HOWEVER THIS SCRIPT CAN BE IMPORTED INTO ANY SCRIPTS THAT REQUIRE REST API CALLS FOR AMP FOR ENDPOINTS.

DEPENDENCIES / REQUIREMENTS:
1- PYTHON 2.7 and 3.6
2- 'requests' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install requests"
'''

import requests
import json

class amp (object):
	"""Class to interact with AMP for Endpoints APIs
	
	Attributes
	A4E_API_hostname: api hostname hor A4E
	A4E_client_id: client ID for A4E
	A4E_api_key: api key for A4E
	
	"""
	
	def __init__(self, A4E_API_hostname, A4E_client_id, A4E_api_key):
		"""Return AMP Object whose attributes are A4E_API_hostname, A4E_client_id and A4E_api_key."""
		self.A4E_API_hostname = A4E_API_hostname
		self.A4E_client_id = A4E_client_id
		self.A4E_api_key = A4E_api_key
		self.headers = {
			'content-type': 'application/json',
			'accept': 'application/json'
			}
	
	def get(self, url):
		
		# Running as a loop since some of the responses may be paginated. So the loop will ensure that it gets all the pages
		fullresponse = {}
		fullresponse['data'] = []
		fullurl = url
		# default - ?offset=0&limit=500
		# first time will always be true
		
		while fullurl:
			response = None
			"""GET method for amp."""
			try:
				response = requests.get(
					"https://{}{}".format(self.A4E_API_hostname, fullurl),
					auth=(self.A4E_client_id, self.A4E_api_key),
					headers=self.headers
				)
				# Consider any status other than 2xx an error
				if not response.status_code // 100 == 2:
					return "Error: Unexpected response {}".format(response.text)
				try:
					json_response = response.json()
					
					if (not len(json_response)):
						break
					
					fullresponse['data'] += json_response['data']
					
					# Move to next page
					if 'next' in json_response['metadata']['links'].keys():
						fullurl = url + '&limit={}&offset={}'.format(json_response['metadata']['results']['items_per_page'],(json_response['metadata']['results']['items_per_page']+json_response['metadata']['results']['index']))
					else:
						fullurl = None
				except:
					return "Error: Non JSON response {}".format(response.text)
			except requests.exceptions.RequestException as e:
				# A serious problem happened, like an SSLError or InvalidURL
				return "Error: {}".format(e)
		return (fullresponse)
	
	def post(self, url, data):
		"""POST method for amp."""
		try:
			response = requests.post(
				"https://{}{}".format(self.A4E_API_hostname, url),
				data=json.dumps(data),
				auth=(self.A4E_client_id, self.A4E_api_key),
				headers=self.headers
			)
			# Consider any status other than 2xx an error
			if not response.status_code // 100 == 2:
				return "Error: Unexpected response {}".format(response.text)
			try:
				return response.json()
			except:
				return "Error: Non JSON response {}".format(response.text)
		except requests.exceptions.RequestException as e:
			# A serious problem happened, like an SSLError or InvalidURL
			return "Error: {}".format(e)
	
	def patch(self, url, data):
		"""PATCH method for amp."""
		try:
			response = requests.patch(
				"https://{}{}".format(self.A4E_API_hostname, url),
				data=json.dumps(data),
				auth=(self.A4E_client_id, self.A4E_api_key),
				headers=self.headers
			)
			# Consider any status other than 2xx an error
			if not response.status_code // 100 == 2:
				return "Error: Unexpected response {}".format(response.text)
			try:
				return response.json()
			except:
				return "Error: Non JSON response {}".format(response.text)
		except requests.exceptions.RequestException as e:
			# A serious problem happened, like an SSLError or InvalidURL
			return "Error: {}".format(e)
	
	def delete(self, url):
		"""DEL method for amp."""
		try:
			response = requests.delete(
				"https://{}{}".format(self.A4E_API_hostname, url),
				auth=(self.A4E_client_id, self.A4E_api_key),
				headers=self.headers
				)
			# Consider any status other than 2xx an error
			if not response.status_code // 100 == 2:
				return "Error: Unexpected response {}".format(response.text)
			try:
				return response.json()
			except:
				return "Error: Non JSON response {}".format(response.text)
		except requests.exceptions.RequestException as e:
				# A serious problem happened, like an SSLError or InvalidURL
				return "Error: {}".format(e)
