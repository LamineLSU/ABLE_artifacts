rule SpecificSampleDetection
{
    meta:
        description = "Detects a specific sample based on its unique code patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 83 F8 01 74 20 FF 75 08 }
        $b = { C1 E8 08 A8 01 75 10 }
        $c = { FF 15 A0 F1 42 00 }
    condition:
        all of them
}