#include <emp-tool/emp-tool.h>
#include "emp-agmpc/RecIO.hpp"
#include "emp-agmpc/RepIO.hpp"
#include "emp-agmpc/emp-agmpc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static char out3[] = "92b404e556588ced6c1acd4ebf053f6809f73a93";//bafbc2c87c33322603f38e06c3e0f79c1f1b1475";


const static int nP = 6;
const int open_num=2;
 
void prove_verify(bool *in,int in_len,block seed,NetIOMP<RecIO,nP> *ios[2],int party,int port){
	const int verifier=nP+1;
	NetIOMP<NetIO,nP+1> *io=new NetIOMP<NetIO,nP+1>(party, port+4*(nP+1)*(nP+1)+3);




	if(party<=nP){

		Hash view_hash;
		view_hash.put(in,in_len);
		view_hash.put(&seed,sizeof(seed));

		for(int r=0;r<2;r++)
		for(int i=1;i<=nP;i++){
			if(i==party)continue;
			if(ios[r]->ios[i]){
				auto &vec=ios[r]->ios[i]->recv_rec;
				view_hash.put(vec.data(),vec.size());//TODO fix
			}
			if(ios[r]->ios2[i]){
				auto &vec=ios[r]->ios2[i]->recv_rec;
				view_hash.put(vec.data(),vec.size());
			}
		}				
		char view_dig[Hash::DIGEST_SIZE];
		view_hash.digest(view_dig);
		io->send_data(verifier,view_dig,Hash::DIGEST_SIZE);

		bool check=false;
		io->recv_data(verifier,&check,1);
		if(!check)return ;

		io->send_data(verifier,in,in_len);
		io->send_data(verifier,&seed,sizeof(seed));

		
		// party send to j    ios->get(j,party<j)
		// party recv from j  ios->get(j,j<party) 

		unsigned long long count=0;
		for(int r=0;r<2;r++)
		for(int i=1;i<=nP;i++){
			if(i==party)continue;
			if(ios[r]->ios[i]){
				auto vec=ios[r]->ios[i]->recv_rec;
				int len=vec.size(); 
				io->send_data(verifier,&len,sizeof(len));
				io->send_data(verifier,vec.data(),len);
				count+=len;
			}
			if(ios[r]->ios2[i]){
				auto vec=ios[r]->ios2[i]->recv_rec;
				int len=vec.size();  
				io->send_data(verifier,&len,sizeof(len));
				io->send_data(verifier,vec.data(),len);
				count+=len;
			}
		}
		cout<<"party "<<party<<" "<<count/1024/1024<<"MB"<<endl;

	}else{
		bool input[512];
		cout<<"verifying"<<endl;

		PRG prg;
		bool check[nP+1];
		memset(check,0,sizeof(check));
		for(int i=1;i<=open_num;i++)
			check[i]=1;
		for(int i=2;i<=nP;i++){
			unsigned int x;
			prg.random_data(&x,sizeof(x));
			swap(check[i],check[x%i+1]);
		}

		char view_dig[nP+1][Hash::DIGEST_SIZE];
		
		char send_dig[nP+1][nP+1][Hash::DIGEST_SIZE];
		char recv_dig[nP+1][nP+1][Hash::DIGEST_SIZE];

		for(int p=1;p<=nP;p++){
			io->recv_data(p,view_dig[p],Hash::DIGEST_SIZE);
			
		}
		for(int p=1;p<=nP;p++){
			io->send_data(p,&check[p],1);
		}
		
		/*char dig[nP+1][Hash::DIGEST_SIZE];
		for(int i=1;i<=nP;i++){
			io->recv_data(i,dig[i],Hash::DIGEST_SIZE);
		}*/


		for(int p=1;p<=nP;p++)if(check[p]){

			Hash view_hash;

			io->recv_data(p,input,in_len);
			view_hash.put(input,in_len);
			block sed;
			io->recv_data(p,&sed,sizeof(sed));
			view_hash.put(&sed,sizeof(sed));
			PRG prng;prng.reseed(&sed);


			NetIOMP<RepIO,nP> rio(p, port);
			NetIOMP<RepIO,nP> rio2(p, port+2*(nP+1)*(nP+1)+1);
			NetIOMP<RepIO,nP> *rios[2] = {&rio, &rio2};



			for(int r=0;r<2;r++)
			for(int i=1;i<=nP;i++){
				if(i==p)continue;
				if(rios[r]->ios[i]){
					auto &vec=rios[r]->ios[i]->recv_rec;
					int len;
					
					io->recv_data(p,&len,sizeof(len)); 
					vec.resize(len);
					io->recv_data(p,vec.data(),len);
					view_hash.put(vec.data(),len);
				}
				if(rios[r]->ios2[i]){
					auto &vec=rios[r]->ios2[i]->recv_rec;
					int len; 

					io->recv_data(p,&len,sizeof(len)); 
					vec.resize(len);
					io->recv_data(p,vec.data(),len);
					view_hash.put(vec.data(),len);
				}
			}

			for(int i=1;i<=nP;i++)if(i!=p){
				Hash hash;
				char tmp[Hash::DIGEST_SIZE];
				for(int r=0;r<2;r++){
					rios[r]->get(i,p<i)->send_hash.digest(tmp);
					hash.put(tmp,Hash::DIGEST_SIZE);
				}
				hash.digest(send_dig[p][i]);
				
				hash.reset();
				for(int r=0;r<2;r++){
					rios[r]->get(i,i<p)->recv_hash.digest(tmp);
					hash.put(tmp,Hash::DIGEST_SIZE);
				}
				hash.digest(recv_dig[i][p]);
			}


			char v_dig[Hash::DIGEST_SIZE];
			view_hash.digest(v_dig);
			if(memcmp(v_dig,view_dig[p],Hash::DIGEST_SIZE)!=0){
				cerr<<"party "<<p<<" commitment is inconsistent"<<endl;
			}
 

			ThreadPool pool(4);	
			string file = circuit_file_location+"/AES-non-expanded.txt";
			file = circuit_file_location+"/sha-1.txt";
			CircuitFile cf(file.c_str()); 

			CMPC<RepIO,nP>* mpc2 = new CMPC<RepIO,nP>(rios, &pool, p, &cf,prng);

 
			mpc2->function_independent();
 
			mpc2->function_dependent(); 

			bool out[160];
			mpc2->online(input, out);

			if(1) { 
				string res = "";
				for(int i = 0; i < cf.n3; ++i)
					res += (out[i]?"1":"0");
				//cout << hex_to_binary(string(out3))<<endl;
				//cout << res<<endl;
				cout << p<<" "<<(res == hex_to_binary(string(out3))? "f(r,w)=View ... yes":"no!")<<endl<<flush;
			}


		}
		for(int i=1;i<=nP;i++)
		for(int j=1;j<=nP;j++)if(i!=j&&check[i]&&check[j]){
			if(memcmp(send_dig[i][j],recv_dig[i][j],Hash::DIGEST_SIZE)!=0){
				cerr<<i<<" "<<j<<" send/recv inconsistent"<<endl;	
			}
		}

		puts("finish");
	}


}


int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int in_len=512;

	if(party==nP+1){
		double st=clock();
		prove_verify(0,in_len,zero_block(),0,party,port);
		cout<<"time : " <<(clock()-st)/CLOCKS_PER_SEC<<endl;
		return 0;
	}

	NetIOMP<RecIO,nP> io(party, port);
	NetIOMP<RecIO,nP> io2(party, port+2*(nP+1)*(nP+1)+1);
	NetIOMP<RecIO,nP> *ios[2] = {&io, &io2};
	ThreadPool pool(4);	
	string file = circuit_file_location+"/AES-non-expanded.txt";
	file = circuit_file_location+"/sha-1.txt";
	CircuitFile cf(file.c_str());

	PRG prng; block seed; prng.random_block(&seed,1); prng.reseed(&seed);
	CMPC<RecIO,nP>* mpc = new CMPC<RecIO,nP>(ios, &pool, party, &cf,prng);

	mpc->function_independent();
	mpc->function_dependent();
	bool in[512]; bool out[160];
	memset(in, false, in_len);	
	mpc->online(in, out);
	if(1) {
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		//cout << hex_to_binary(string(out3))<<endl;
		//cout << res<<endl;
		cout << (res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl<<flush;
	}




	prove_verify(in,in_len,seed,ios,party,port);
	
 

	delete mpc;
	return 0;
}
