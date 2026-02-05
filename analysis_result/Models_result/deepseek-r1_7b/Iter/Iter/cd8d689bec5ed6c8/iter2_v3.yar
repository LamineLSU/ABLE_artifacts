rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {8B C8 5A E8 CE E8 C3 ??}          # Targets initial TEST EAX and related calls
        $pattern1 = {E8 C8 F0 F0 00 00 FF EE FF DD C1 BB ??}  # Targets specific call sequence in another trace
        $pattern2 = {6A 5B 74 12 8B CE E8 FF FF FE FF FC ??:}   # Targets a distinct instruction pattern with wildcards

    condition:
        any of them
}