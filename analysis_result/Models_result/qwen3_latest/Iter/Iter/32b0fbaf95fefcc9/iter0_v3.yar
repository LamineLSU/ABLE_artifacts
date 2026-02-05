rule EvasionDetection {
    meta:
        description = "Detects evasion via call to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }
        $b = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }
        $c = { FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        any of them
}