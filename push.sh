#!/bin/sh

git add .

git commit -m "test"

git push

hexo clean;hexo g;hexo d
