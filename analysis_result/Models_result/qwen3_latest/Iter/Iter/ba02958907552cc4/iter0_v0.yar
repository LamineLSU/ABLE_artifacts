rule SandboxEvasionCheck {
    meta:
        description = "Detects sandbox evasion checks by analyzing ExitProcess and handle validation patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 74 12 6A 5B }
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}