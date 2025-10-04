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
        - name: description
            - contains mouse move: moves mouse given coords in sentence seperated by comma
        - code: key code
            - 999 = Delay
            - 800 - 900 = mouse input
                - 801: left click
                - 802: right click
                - 804: moving mouse
            - 987 = Command (runs command in sentence property that can be run in cmd)
            - everything else are key presses
        - held: if the key is held e.g. for alt + tab. Alt is held and tab is not held
            - Key has to be added again to release the key with held set to false
        - sentence: 
            - 998: adding sentence, adds the sentence into the app or website
            - 997: Base64 string to convert back into normal string
            - 996: Adds code e.g. sql and JavaScript
            - 995: Adds csv line after split by comma by index. parses sentence as usize (int) for index position
        - loop: how many times this object is used
        - time: mainly for Delay in seconds