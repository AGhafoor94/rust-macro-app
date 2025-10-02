# Windows API with RUST

## Description

Trying to learn about creating automated process using json to press keys and move mouse.
Creates a log on what action is performed.

#### JSON format

- App name: Name of file (not read by app)
- Description: Description of the macro (not read by app)
- loop: Amount to times the steps are run. Can be updated by a csv list
- hotkey: 2 Key codes to use seperated by a comma e.g. "160, 52". App waits for them to be pressed and continues once done
- readCsv: Reads a CSV file given a path
- app array:
    - appValue: website / app exe
    - websiteOpen: true or false (appValue -> exe ? false)
    - steps array:
        - name: description (not read by app)
        - code: key code
            - 999 = Delay
            - 800 - 900 = mouse input
            - 987 = Command (runs command in sentence property that can be run in cmd)
            - everything else are key presses
        - held: if the key is held e.g. for alt + tab. Alt is held and tab is not held
        - sentence: (code has to be 998), adding sentence, adds the sentence into the app or website
        - loop: how many times this object is used