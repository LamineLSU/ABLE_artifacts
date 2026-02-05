rule SampleRule
{
    meta:
        description = "Detects a specific code sequence in memory"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 95

    strings:
        $a = { 85 C0 74 12 68 00 00 00 00 }
        $b = { E8 25 05 00 00 85 C0 }
        $c = { FF 15 2C A1 08 00 }

    condition:
        all of them
}