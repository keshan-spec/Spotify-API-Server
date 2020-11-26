import { Field, ObjectType } from "type-graphql";
import { Entity, Column, BaseEntity, PrimaryColumn } from "typeorm";

@ObjectType()
@Entity("users")
export class User extends BaseEntity {

    @Field()
    @PrimaryColumn()
    user_id: string;

    @Field()
    @Column()
    email: string;


    @Field()
    @Column()
    spotify_code: string;


    @Field()
    @Column()
    password: string;

    @Column("int", { default: 0 })
    tokenVersion: number
}
