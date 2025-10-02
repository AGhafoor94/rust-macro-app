# Windows API with RUST

## Description

Trying to learn about creating automated process using json to press keys and move mouse

#### JSON format

- App name: Description of file (not read by app)
- app array:
    - appValue: website / app exe
    - websiteOpen: true or false (appValue -> exe ? false)
    - steps array:
        - name: description (not read by app)
        - code: key code
            - 999 = Delay
            - 800 - 900 = mouse input
            - everything else are key presses
        - held: if the key is held e.g. for alt + tab. Alt is held and tab is not held
        - sentence: (code has to be 998), adding sentence, adds the sentence into the app or website
        - loop: how many times this object is used