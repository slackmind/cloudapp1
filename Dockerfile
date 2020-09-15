FROM node:12

WORKDIR /usr/src/app

COPY . /usr/src/app

# install 
RUN npm install
ENV microsoftKey = c8c62ec3e50a43faaf1df63ffbad697c
ENV virusTotalKey = ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca
ENV newsKey = c61555335ae647768b810bcdeef93736



# open the machine to the world
EXPOSE 3000

# start the app
CMD ["npm", "start"]