rule EvasionCheck {
    meta:
        description = "Detects potential evasion checks and termination logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 6A 00 FF 15 ?? ?? ?? ?? }
        $b = { 85 C0 FF 15 ?? ?? ?? ?? }
        $c = { 3D 97 00 00 00 75 ?? }
    condition:
        all of them
}