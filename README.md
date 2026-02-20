# events-backend

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)

## Running the server

```bash
npm run dev
```

This builds the app image, starts Postgres, runs migrations, and starts the server at `http://localhost:3000`.

### Other commands

```bash
npm run dev:down   # stop all containers
npm run dev:reset  # wipe the database and restart from scratch
```
