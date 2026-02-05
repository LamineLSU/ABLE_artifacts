rule MaliciousCodeDetection
{
    meta:
        description = "Detects a sequence of instructions indicative of malicious behavior"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
        $b = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $c = { 55 8B EC FF 75 08 }
    condition:
        all of them
}