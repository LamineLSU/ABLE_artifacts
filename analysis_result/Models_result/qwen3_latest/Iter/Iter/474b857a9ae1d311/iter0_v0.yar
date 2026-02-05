rule SuspiciousExitCall
{
    meta:
        description = "Detects suspicious call patterns potentially used for exit or control flow hijacking."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        category = "Malware Analysis"

    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // push ebp, mov ebp, push [ebp+08h], call (offset)
        $b = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }    // pop ecx, push [ebp+08h], call (address)
        $c = { FF 75 08 E8 ?? ?? ?? ?? 59 }       // push [ebp+08h], call (offset), pop ecx

    condition:
        all of ($a or $b or $c)
}