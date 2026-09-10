# North Country Herbal Supplements

North Country Herbal Supplements is a full-stack e-commerce web application built to demonstrate a secure online shopping and checkout experience. The project includes product browsing, cart and checkout functionality, user authentication, database integration, payment processing, and ZIP-code-based sales tax calculations. Note that this is a demo and not for practical use.

## Features

- E-commerce storefront for herbal supplement products
- Shopping cart and checkout workflow
- User authentication and password hashing with Argon2
- MySQL database integration
- Stripe payment integration
- ZIP-code-based sales tax calculation using tax-rate data
- Cookie-based session functionality
- Responsive web interface
- Security-focused checkout design

## Technologies Used

- HTML
- CSS
- JavaScript
- Node.js
- MySQL
- mysql2
- Argon2
- Stripe API
- Cookies

## Project Structure

The repository contains the frontend and backend files for the store along with sales-tax datasets used by the checkout system. Sensitive configuration values such as database credentials, API secrets, certificates, and environment variables should remain outside version control and be protected through `.gitignore` and environment configuration.

## Setup

1. Clone the repository.
2. Install Node.js dependencies with `npm install`.
3. Configure the required database and application environment variables locally.
4. Set up the MySQL database used by the application.
5. Add the required Stripe credentials to your local environment configuration.
6. Start the application using the project's server entry point.
7. Open the local application address in your browser. For this instance, https://localhost:8080/

## Security

This project is designed with secure web-development practices in mind. Passwords are hashed using Argon2, sensitive credentials should not be committed to GitHub, and payment processing is integrated through Stripe rather than storing raw payment-card information in the application.

## Purpose

This project was created as a hands-on demonstration of full-stack web development, database management, authentication, secure checkout design, payment integration, and practical web security concepts.

## Author

Theo Cseledy
