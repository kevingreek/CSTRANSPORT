#include "TextHelp.hpp"
#include <string.h>

using namespace std;

// --------------------------------------------------------------------------------
std::string _text_help::get_field_from_st(const std::string &in,char delim,int f_n)
{
    int c_f=0;
    std::string::size_type pos_b=0;
    std::string::size_type pos_e=0;
    while(1)
    {
//        if (in[pos_e]==' ' || pos_e==in.length() || in[pos_e]=='\r' || in[pos_e]==';')
        if (in[pos_e]==delim || pos_e==in.length())
        {
            if (f_n==c_f)
            {
                return std::string(in,pos_b,pos_e-pos_b);
            }
            pos_b=pos_e+1;
            if (pos_e==in.length()) return "";
            c_f++;
        }
        pos_e++;
    }
}

// --------------------------------------------------------------------------------
std::string _text_help::get_field_from_st(const std::string &in,const char *delim,int f_n)
{
    int c_f=0;
    std::string::size_type pos_b=0;
    std::string::size_type pos_e=0;
    while(1)
    {
        if (strchr(delim,in[pos_e]) || pos_e==in.length())
        {
            if (f_n==c_f)
            {
                return std::string(in,pos_b,pos_e-pos_b);
            }
            pos_b=pos_e+1;
            if (pos_e==in.length()) return "";
            c_f++;
        }
        pos_e++;
    }
}

// --------------------------------------------------------------------------------
void _text_help::split_text_by(const std::string &text,const char *delim,list<std::string> &l)
{
    l.clear();

    int delim_len=strlen(delim);

    std::string::size_type old_pos=0;
    while(1)
    {
        std::string::size_type pos=text.find(delim,old_pos);
        if (pos==std::string::npos) break;

        l.push_back(std::string(text,old_pos,pos-old_pos));

        old_pos=pos+delim_len;
    }

    if (old_pos!=text.length()) l.push_back(std::string(text,old_pos,text.length()-old_pos));
}

// --------------------------------------------------------------------------------
void _text_help::split_text_by_endl(const std::string &text,list<std::string> &l)
{
    l.clear();

    std::string::size_type old_pos=0;
    while(1)
    {
		// We MUST have \n in both cases - in case \n and in \r\n case
		// so, search \n
        std::string::size_type pos=text.find('\n',old_pos);
		if (pos==std::string::npos) break;

		int len=1;

		// check \r befor \n
		if (pos!=0)
		{
			if (text[pos-1]=='\r')
			{
				pos--;
				len=2;
			}
		}

        l.push_back(std::string(text,old_pos,pos-old_pos));

        old_pos=pos+len;
    }

    if (old_pos<text.length()) l.push_back(std::string(text,old_pos,text.length()-old_pos));
}

// --------------------------------------------------------------------------------
void _text_help::string_to_map(const std::string &in,std::map<string,string> &m,char delim)
{
    m.clear();

    std::string::size_type pos=0;
    std::string::size_type len=in.length();

    while(pos<len)
    {
        if (in[pos]==delim)
        {
            std::string::size_type lpos=pos;
            while(1)
            {
                if (in[lpos]==' ' || in[lpos]=='\r' || in[lpos]=='\n' || (lpos!=pos && in[lpos]=='=')) { lpos++; break; }
                if (lpos==0) break;
                lpos--;
            }

            std::string param=std::string(in,lpos,pos-lpos);
            if (param.empty()) { pos++; continue; }

            pos++;
            // may be "p1=" or "p1= " and so on
            if (pos==len || in[pos]==' ' || in[pos]=='\r' || in[pos]=='\n')
            {
                m[param]="";
                continue;
            }

            std::string::size_type rpos=pos;
            while(rpos<len)
            {
                if (in[rpos]==' ' || in[rpos]=='\r' || in[rpos]=='\n') break;
                rpos++;
            }
            m[param]=std::string(in,pos,rpos-pos);
        }

        pos++;
    }
}

// --------------------------------------------------------------------------------
bool _text_help::is_dig_value(const std::string &s)
{
    std::string::const_iterator i=s.begin();
    while(i!=s.end())
    {
        if ((*i)<'0' || (*i)>'9') return false;
        i++;
    }
    return true;
}

// --------------------------------------------------------------------------------
std::string _text_help::get_param_value_from_st(const std::string &in,const std::string &param)
{
    std::string::size_type pos=in.find(param+"=");
    if (pos==std::string::npos) return "";

    pos+=param.length()+1;

    bool use_quot=false;
    if (in[pos]=='"')
    {
        pos++;
        return get_field_from_st(string(in,pos,in.length()-pos),'"',0);
    }

    return get_field_from_st(string(in,pos,in.length()-pos)," ,;\r",0);
}
