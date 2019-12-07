# NRGScoutingAPI
An API built for efficiency, speed, and ease of use of The Blue Alliance.
The Blue Alliance is powerful. But its complicated to setup and sends back more than you need for basic scouting app actions in FRC.
There's already limited data at competitions, and teams can't waste it on making requests for (less than) half useful data.

## What does the api do?
Our API wraps around The Blue Alliance's API to prive essential stats such as
- active teams in a given year
- teams at a given competition
- match pairings for a given competition
- competition event codes
- more wrappers to come soon...

## How does it work?
The API essentially strips TBA's servers for the data we need and simplifies it to the parts that are actually useful for most tasks.
In addition, we cache specific requests, so subsequent requests will run faster, up to 30 times faster in cases of larger queries.
