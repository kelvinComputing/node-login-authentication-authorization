import { bcryptAdapter, envs, JwtAdapter } from "../../config";
import { UserModel } from "../../data";
import { CustomError, LoginUserDto, RegisterUserDto } from "../../domain";
import { UserEntity } from "../../domain/entities/user.entity";
import { EmailService } from "./email.service";


export class AuthService {

    constructor(

        private readonly emailService: EmailService,
    ){}

    public async registerUser( RegisterUserDto: RegisterUserDto ) {

        const existUser = await UserModel.findOne({ email: RegisterUserDto.email });

        if ( existUser ) throw CustomError.badRequest('Email already exist');

        try {
            const user = new UserModel(RegisterUserDto);
            
            //Encriptar la contraseña
            user.password = bcryptAdapter.hash( RegisterUserDto.password );
            
            
            await user.save(); 

            //JWT <---- mantener la autenticacion del usuario


            // Email de confirmacion
            await this.sendEmailValidationLink( user.email );

            const { password, ...userEntity } = UserEntity.fromObject(user);

            const token = await JwtAdapter.generateToken({ id: user.id });
            if ( !token ) throw  CustomError.internalServer('Error while creating JWT')
            

            return { 
                user: userEntity,
                token: token, 
            };
        } catch (error) {
            throw CustomError.internalServer(`${ error }`);
        }
    }

    public async loginUser( loginUserDto: LoginUserDto ) {

        const user = await UserModel.findOne({ email: loginUserDto.email });
        if (!user) throw CustomError.badRequest('Email not exist');

        const isMatching = bcryptAdapter.compare( loginUserDto.password, user.password );
        if ( !isMatching ) throw CustomError.badRequest('Password is not valid');

        const { password, ...userEntity } = UserEntity.fromObject( user );

        const token = await JwtAdapter.generateToken({ id: user.id, email: user.email });
        if ( !token ) throw  CustomError.internalServer('Error while creating JWT')


        return {
            user: userEntity,
            token: token
        }
    }

    private sendEmailValidationLink = async( email: string ) =>{

        const token = await JwtAdapter.generateToken({ email });
        if (!token) throw CustomError.internalServer('Error getting Token ');

        const link = `${ envs.WEBSERVICE_URL }/auth/validate-email/${ token }`;
        const html = `
            <h1>Validate your email</h1>
            <p>Click on the following link to validate yor email</p>
            <a href="${ link }">Validate your email: ${ email }</a>
        `;

        const options = {
            to: email,
            subject: 'Validate your email',
            htmlBody: html,
        }

        const isSent = await this.emailService.sendEmail(options);
        if( !isSent ) throw CustomError.internalServer('Error sending email');

        return true;
    }

    public validateEmail = async(token:string) =>{
        const payload = await JwtAdapter.validateToken(token);
        if( !payload ) throw CustomError.unauthorized('Invalid Token');
    
        const { email } = payload as { email:string };
        if( !email ) throw CustomError.internalServer('Email not in token');
    
        const user = await UserModel.findOne({ email });
        if( !user ) throw CustomError.internalServer('Email not exists');
    
        user.emailValidated = true;
        await user.save();
    
        return true;
    } 

}