CXX=g++
CPPFLAGS=-g -std=c++11 -lpcap
all:
	$(CXX) $(CPPFLAGS) isashark.cpp -o isashark