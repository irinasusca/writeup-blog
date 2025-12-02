#!/bin/bash
# deploy-blog.sh

# build Hugo site
hugo -d docs

# add all changes
git add .

# commit with a generic message
git commit -m "update: new post or changes"

# push to GitHub
git push origin main

