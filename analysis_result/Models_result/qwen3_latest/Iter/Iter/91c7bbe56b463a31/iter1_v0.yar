rule ExampleRule {
    meta:
        description = "Example rule demonstrating pattern matching in YARA"
    strings:
        $a = { FF1574304200 83BC245006000006 744C }
        $b = { FF1584304200 83F8FF 7508 }
        $c = { FF1554304200 51 52 50 FF15?? ?? ?? ?? }
    condition:
        any of them
}