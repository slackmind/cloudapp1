FROM node:12 

# our working directory
WORKDIR /app

# copy all to working directory
COPY . /app

# install 
RUN npm install

# required to access the APIs
ENV MSFKEY=c8c62ec3e50a43faaf1df63ffbad697c
ENV VTKEY=ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca
ENV NEWSKEY=c61555335ae647768b810bcdeef93736

# open the machine to the world
EXPOSE 3000

# start the app
CMD ["npm", "start"]