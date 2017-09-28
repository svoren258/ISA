CXX=g++
CPPFLAGS=-g -pthread -std=c++11
all:
	$(CXX) $(CPPFLAGS) isashark.cpp -o isashark -lcrypto