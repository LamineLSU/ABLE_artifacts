rule CustomPattern
{
    meta:
        description = "Matches three distinct patterns from a disassembled code snippet."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"

    strings:
        $pattern0 = { 55 8B EC FF 75 ?? E8 ?? ?? ?? ?? }
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? }
        $pattern2 = { FF 75 ?? E8 ?? ?? ?? ?? }

    condition:
        all of them
}