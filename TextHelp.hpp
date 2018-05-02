#ifndef __TEXT_HELP_FUNCTIONS__
#define __TEXT_HELP_FUNCTIONS__

#include <string>
#include <list>
#include <map>

namespace _text_help
{
    std::string get_field_from_st(const std::string &in,char delim,int f_n);
    std::string get_field_from_st(const std::string &in,const char *delim,int f_n);

    void split_text_by(const std::string &text,const char *delim,std::list<std::string> &l);
	void split_text_by_endl(const std::string &text,std::list<std::string> &l);

	// make map - key is left side from delim word, value is right side word
	// Example 1 "param1=value1 param2=value2", delim='=' -> m[param1]=value1, m[param2]=value2
	// Example 2 "param1=value1\r\nparam2=value2", delim='=' -> m[param1]=value1, m[param2]=value2
	void string_to_map(const std::string &in,std::map<std::string,std::string> &m,char delim = '=');

	bool is_dig_value(const std::string &n);

	std::string get_param_value_from_st(const std::string &in,const std::string &param);
};

#endif
