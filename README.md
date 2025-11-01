# Site de Questions pour Langues Vivantes

Application web pour les tests d'aptitude et formulaires de langues vivantes.

## Fonctionnalités

- Authentification des utilisateurs (enseignants)
- Test d'aptitude initial
- Formulaires spécifiques par matière
- Suivi de progression

## Déploiement sur Netlify

### Prérequis

- Compte Netlify
- Node.js et npm installés

### Instructions de déploiement

1. Clonez ce dépôt
2. Installez les dépendances : `npm install`
3. Connectez-vous à Netlify : `npx netlify login`
4. Déployez le site : `npx netlify deploy --prod`

### Variables d'environnement à configurer

Dans les paramètres de votre site Netlify, configurez les variables d'environnement suivantes :

- `SESSION_SECRET` : Clé secrète pour les sessions (générez une chaîne aléatoire)
- `NODE_ENV` : Définir à `production` pour l'environnement de production

## Développement local

1. Installez les dépendances : `npm install`
2. Démarrez le serveur de développement : `npm start` ou `npm run dev` pour utiliser Netlify Dev
3. Accédez à l'application sur http://localhost:3000

## Structure du projet

- `/public` : Fichiers statiques (HTML, CSS, JS client)
- `/data` : Fichiers de données JSON
- `/functions` : Fonctions serverless pour Netlify
- `server.js` : Serveur Express pour le développement local
