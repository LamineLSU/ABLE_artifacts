rule MaliciousCodePattern
{
    meta:
        description = "Detects potential malicious control flow patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $b = { FF 75 08 E8 ?? ?? ?? ?? }
        $c = { 59 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}