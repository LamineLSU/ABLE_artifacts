rule CustomRule {
    meta:
        author = "Your Name"
        description = "Custom rule for bypassing detection based on specific call patterns"

    strings:
        $pattern0 = { FF 15 20 75 45 00 }
        $pattern1 = { FF 15 84 75 45 00 }
        $pattern2 = { FF 15 84 74 45 00 }

    condition:
        any of them
}