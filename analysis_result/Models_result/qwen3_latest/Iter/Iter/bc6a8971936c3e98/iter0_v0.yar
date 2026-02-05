rule SandboxEvasion {
    meta:
        description = "Detects sandbox evasion via memory checks and exits"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }
        $b = { 57 FF 15 ?? ?? ?? ?? 6A 04 }
        $c = { FF 75 FC FF 15 ?? ?? ?? ?? }
    condition:
        any of ($a, $b, $c)
}