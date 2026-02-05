rule ExitProcess_Detection
{
    meta:
        description = "Detects the ExitProcess call or related control flow patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 83 C4 ?? 52 FF D0 }
        $b = { 8B 55 ?? 8B 06 83 C4 ?? 52 FF D0 }
        $c = { 50 E8 ?? ?? ?? ?? 8B 55 ?? }

    condition:
        any of ($a, $b, $c)
}