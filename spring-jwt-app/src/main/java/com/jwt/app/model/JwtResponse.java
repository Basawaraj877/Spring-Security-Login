package com.jwt.app.model;

import lombok.Builder;

@Builder
public class JwtResponse {

		private String jwtToken;
		//private String email;
		public JwtResponse() {
			super();
		}
		public JwtResponse(String jwtToken) {
			super();
			this.jwtToken = jwtToken;
			//this.email = email;
		}
		public String getJwtToken() {
			return jwtToken;
		}
		public void setJwtToken(String jwtToken) {
			this.jwtToken = jwtToken;
		}
//		public String getEmail() {
//			return email;
//		}
//		public void setEmail(String email) {
//			this.email = email;
//		}
		@Override
		public String toString() {
			return "JwtResponse [jwtToken=" + jwtToken +"]";
		}
		
		
		// Builder class for JwtResponse
	    public static class JwtResponseBuilder {
	        private String jwtToken;
	       // private String email;

	        public JwtResponseBuilder withJwtToken(String jwtToken) {
	            this.jwtToken = jwtToken;
	            return this;
	        }

//	        public JwtResponseBuilder withUsername(String email) {
//	            this.email = email;
//	            return this;
//	        }

	        public JwtResponse build() {
	            JwtResponse response = new JwtResponse();
	            response.jwtToken = this.jwtToken;
	            //response.email = this.email;
	            return response;
	        }
	    }

	    // Static method to create a builder
	    public static JwtResponseBuilder builder() {
	        return new JwtResponseBuilder();
	    }
		
		
}
