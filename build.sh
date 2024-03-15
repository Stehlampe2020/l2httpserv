#!/usr/bin/env bash

printf "\nDetecting native python3... "
native_pyver="$(python3 --version)"
if [ $? == 0 ]
then
    printf "$native_pyver detected!\n" &&
    python3 -m pip install --upgrade Pillow PyInstaller &&
    printf "\nCleaning up / creating build area...\n" &&
    rm -rf ./build.linux && mkdir ./build.linux && cd ./build.linux &&
    printf "\nBuilding l2httpserv...\n" &&
    python3 -m PyInstaller --clean --icon=lampe2020_logo.png --onefile ../main.py &&
    printf "\nCopying out built binary...\n" &&
    cp -r ./dist/main ../l2httpserv
else
    printf "No native python3 detected! (Status code: $?)\n"
fi

printf "\nAttempting .exe build in WINE...\n"
wine build