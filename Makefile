CXX=g++
CPPFLAGS=-g -pthread -std=c++11 -lpcap
all:
	$(CXX) $(CPPFLAGS) isashark.cpp -o isashark