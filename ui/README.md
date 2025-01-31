# Fanal-ui

[![KhulnaSoft Ecosystem Repository](https://github.com/khulnasoft/evolution/blob/main/repos/badges/fanal-ecosystem-blue.svg)](https://github.com/khulnasoft/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/khulnasoft/evolution/blob/main/REPOSITORIES.md#incubating)


![release](https://flat.badgen.net/github/release/khulnasoft/fanal/ui/latest?color=green) ![last commit](https://flat.badgen.net/github/last-commit/khulnasoft/fanal/ui) ![licence](https://flat.badgen.net/badge/license/Apache/blue) ![docker pulls](https://flat.badgen.net/docker/pulls/khulnasoft/fanal/ui?icon=docker)

## Description

A simple WebUI for displaying latest events from [KhulnaSoft](https://khulnasoft.com). It works as output for [Fanal](https://github.com/khulnasoft/fanal).

## Requirements

Events are stored in a `Redis` server with [`Redisearch`](https://github.com/RediSearch/RediSearch) module (> v2).

## Usage

### Options
#### Precedence: flag value -> environment variable value -> default value

```shell
Usage of Fanal-UI:  
-a string
      Listen Address (default "0.0.0.0", environment "FANAL_UI_ADDR")
-d boolean
      Disable authentication (environment "FANAL_UI_DISABLEAUTH")
-l string   
      Log level: "debug", "info", "warning", "error" (default "info",  environment "FANAL_UI_LOGLEVEL")
-p int
      Listen Port (default "2802", environment "FANAL_UI_PORT")
-r string
      Redis server address (default "localhost:6379", environment "FANAL_UI_REDIS_URL")
-t string
      TTL for keys, the format is X<unit>,
      with unit (s, m, h, d, W, M, y)" (default "0", environment "FANAL_UI_TTL")
-u string  
      User in format <login>:<password> (default "admin:admin", environment "FANAL_UI_USER")
-v boolean
      Display version
-w string  
      Redis password (default "", environment "FANAL_UI_REDIS_PASSWORD")
-x boolean
      Allow CORS for development (environment "FANAL_UI_DEV")
```

> If not user is set and the authentication is not disabled, the default user is `admin:admin`

### Run with docker

```shell
docker run -d -p 2802:2802 khulnasoft/fanal/ui
```

### Run

```
git clone https://github.com/khulnasoft/fanal/ui.git
cd fanal-ui

go run .
#or
make fanal-ui && ./fanal-ui
```

### Endpoints

| Route   | Method | Query Parameters | Usage            |
| :------ | :----: | :--------------- | :--------------- |
| `/docs` | `GET`  | none             | Get Swagger Docs |
| `/`     | `GET`  | none             | Display WebUI    |

#### UI

The UI is reachable by default at `http://localhost:2802/`.

#### API

> The prefix for access to the API is `/api/v1/`.
> The base URL for the API is `http://localhost:2802/api/v1/`.

| Route                       | Method | Query Parameters                                                         | Usage                                |
| :-------------------------- | :----: | :----------------------------------------------------------------------- | :----------------------------------- |
| `/`                         | `POST` | none                                                                     | Add event                            |
| `/healthz`                  | `GET`  | none                                                                     | Healthcheck                          |
| `/authenticate`, `/auth`    | `POST` | none                                                                     | Authenticate                         |
| `/configuration`, `/config` | `GET`  | none                                                                     | Get Configuration                    |
| `/outputs`                  | `GET`  | none                                                                     | Get list of Outputs of Fanal |
| `/event/count`              | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Count all events                     |
| `/event/count/priority`     | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Count events by priority             |
| `/event/count/rule`         | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Count events by rule                 |
| `/event/count/source`       | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Count events by source               |
| `/event/count/tags`         | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Count events by tags                 |
| `/event/search`             | `GET`  | `pretty`, `priority`, `rule`, `filter`, `tags`, `since`, `limit`, `page` | Search events                        |

All responses are in JSON format.

Query parameters list:
* `pretty`: return well formated JSON
* `priority`: filter by priority
* `rule`: filter by rule
* `filter`: filter by term
* `source`: filter by source
* `tags`: filter by tags
* `since`: filter by since (in 'second', 'min', 'day', 'week', 'month', 'year')
* `limit`: limit number of results (default: 100)
* `page`: page of results

## Development

### Start local redis server

```shell
docker run -d -p 6379:6379 redislabs/redisearch:2.2.4
```

### Build

Requirements:
* `go` >= 1.18
* `nodejs` >= v14
* `yarn` >= 1.22

```shell
make fanal-ui
```

### Lint

```shell
make lint
```

### Full lint

```shell
make lint-full
```

### Update Docs

Requirement:
* [`swag`](https://github.com/swaggo/swag)

```shell
make docs
```

## Screenshots

![fanal-ui](imgs/webui_01.png)
![fanal-ui](imgs/webui_02.png)
![fanal-ui](imgs/webui_03.png)
![fanal-ui](imgs/webui_04.png)
![fanal-ui](imgs/webui_05.png)

## Authors

* Thomas Labarussias (https://github.com/Issif)
* Frank Jogeleit (https://github.com/fjogeleit)
